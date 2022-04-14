// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	cache "github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/tevino/abool"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	logModuleInfo = "server"
)

var (
	OIDCCallbackPath      = "/oidc/callback"
	SessionLogoutPath     = "/logout"
	authenticatorsMapping = []string{
		0: "session authenticator",
		1: "idtoken authenticator",
		2: "JWT access token authenticator",
		3: "kubernetes authenticator",
	}
)

func init() {
	// Register type for claims.
	gob.Register(map[string]interface{}{})
	gob.Register(oauth2.Token{})
	gob.Register(oidc.IDToken{})
}

type server struct {
	provider                *oidc.Provider
	oauth2Config            *oauth2.Config
	store                   sessions.Store
	oidcStateStore          sessions.Store
	bearerUserInfoCache     *cache.Cache
	authenticators          []authenticator.Request
	authorizers             []Authorizer
	afterLoginRedirectURL   string
	homepageURL             string
	afterLogoutRedirectURL  string
	sessionMaxAgeSeconds    int
	strictSessionValidation bool

	cacheEnabled            bool
	cacheExpirationMinutes  int

	authHeader              string
	idTokenOpts             jwtClaimOpts
	upstreamHTTPHeaderOpts  httpHeaderOpts
	userIdTransformer       UserIDTransformer
	caBundle                []byte
	sessionSameSite         http.SameSite
}

// jwtClaimOpts specifies the location of the user's identity inside a JWT's
// claims.
type jwtClaimOpts struct {
	userIDClaim string
	groupsClaim string
}

// httpHeaderOpts specifies the location of the user's identity and
// authentication method inside HTTP headers.
type httpHeaderOpts struct {
	userIDHeader     string
	userIDPrefix     string
	groupsHeader     string
	authMethodHeader string
}

func (s *server) authenticate(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r, logModuleInfo)
	logger.Info("Authenticating request...")

	var userInfo user.Info
	for i, auth := range s.authenticators {
		var cacheKey string

		if s.cacheEnabled {
			// If the cache is enabled, check if the current authenticator implements the Cacheable interface.
			cacheable := reflect.TypeOf((*Cacheable)(nil)).Elem()
			isCacheable := reflect.TypeOf(auth).Implements(cacheable)

			if isCacheable {
				// Store the key that we are going to use for caching UserDetails.
				// We store it before the authentication, because the authenticators may mutate the request object.
				logger.Debugf("Retrieving the cache key...")
				cacheableAuthenticator := reflect.ValueOf(auth).Interface().(Cacheable)
				cacheKey = cacheableAuthenticator.getCacheKey(r)
			}
		}

		if cacheKey != "" {
			// If caching is enabled, try to retrieve the UserInfo from cache.
			userInfo = s.getCachedUserInfo(cacheKey, r)

			if userInfo != nil {
				logger.Infof("Successfully authenticated request using the cache.")
				logger.Infof("UserInfo: %+v", userInfo)
				break
			}
		}

		logger.Infof("%s starting...", strings.Title(authenticatorsMapping[i]))
		resp, found, err := auth.AuthenticateRequest(r)
		if err != nil {
			logger.Errorf("Error authenticating request using %s: %v", authenticatorsMapping[i], err)
			// If we get a login expired error, it means the authenticator
			// recognised a valid authentication method which has expired
			var expiredErr *loginExpiredError
			if errors.As(err, &expiredErr) {
				returnMessage(w, http.StatusUnauthorized, expiredErr.Error())
				return
			}

			// If AuthService encountered an authenticator-specific error,
// then no other authentication methods will be tested.
			var authnError *authenticatorSpecificError
			if errors.As(err, &authnError) {
				returnMessage(w, http.StatusUnauthorized, authnError.Error())
				return
			}

		}
		if found {
			logger.Infof("Successfully authenticated request using %s", authenticatorsMapping[i])
			userInfo = resp.User
			logger.Infof("UserInfo: %+v", userInfo)

			if cacheKey != "" {
				// If cache is enabled and the current authenticator is Cacheable, store the UserInfo to cache.
				logger.Infof("Caching authenticated UserInfo...")
				s.bearerUserInfoCache.Set(cacheKey, userInfo, time.Duration(s.cacheExpirationMinutes)*time.Minute)
			}
			break
		}
	}
	if userInfo == nil {
		logger.Infof("Failed to authenticate using authenticators. Initiating OIDC Authorization Code flow...")
		// TODO: Detect "X-Requested-With" header and return 401
		s.authCodeFlowAuthenticationRequest(w, r)
		return
	}

	logger = logger.WithField("user", userInfo)
	logger.Info("Authorizing request...")

	for i, authz := range s.authorizers {
		allowed, reason, err := authz.Authorize(r, userInfo)
		if err != nil {
			logger.Errorf("Error authorizing request using authorizer %d: %v", i, err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// If the request is not allowed, try to revoke the user's session.
		// TODO: Only revoke if the authenticator that provided the identity is
		// the session authenticator.
		if !allowed {
			logger.Infof("Authorizer '%d' denied the request with reason: '%s'", i, reason)
			session, _, err := sessionFromRequest(r, s.store, userSessionCookie, s.authHeader)
			if err != nil {
				logger.Errorf("Error getting session for request: %v", err)
			}
			if !session.IsNew {
				err = revokeOIDCSession(r.Context(), w, session, s.provider, s.oauth2Config, s.caBundle)
				if err != nil {
					logger.Errorf("Failed to revoke session after authorization fail: %v", err)
				}
			}
			// TODO: Move this to the web server and make it prettier
			msg := fmt.Sprintf("User '%s' failed authorization with reason: %s. "+
				"Click <a href='%s'> here</a> to login again.", userInfo.GetName(),
				reason, s.homepageURL)

			returnHTML(w, http.StatusForbidden, msg)
			return
		}
	}

	for k, v := range userInfoToHeaders(userInfo, &s.upstreamHTTPHeaderOpts, &s.userIdTransformer) {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
	return
}

// getCachedUserInfo returns the UserInfo if it's in the cache
// using the key: 'cacheKey' or it returns nil.
func (s *server) getCachedUserInfo(cacheKey string, r *http.Request) user.Info {
	logger := loggerForRequest(r, logModuleInfo)

	cachedUserInfo, found := s.bearerUserInfoCache.Get(cacheKey)
	if found {
		userInfo := cachedUserInfo.(user.Info)
		logger.Infof("Found Cached UserInfo: %+v", userInfo)
		return userInfo
	}
	logger.Info("The UserInfo is not cached.")
	return nil
}

// authCodeFlowAuthenticationRequest initiates an OIDC Authorization Code flow
func (s *server) authCodeFlowAuthenticationRequest(w http.ResponseWriter, r *http.Request) {
	logger := loggerForRequest(r, logModuleInfo)

	// Initiate OIDC Flow with Authorization Request.
	state, err := createState(r, w, s.oidcStateStore)
	if err != nil {
		logger.Errorf("Failed to save state in store: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Failed to save state in store.")
		return
	}

	http.Redirect(w, r, s.oauth2Config.AuthCodeURL(state), http.StatusFound)
}

// callback is the handler responsible for exchanging the auth_code and retrieving an id_token.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r, logModuleInfo)

	// Get authorization code from authorization response.
	var authCode = r.FormValue("code")
	if len(authCode) == 0 {
		logger.Warnf("Missing url parameter: code. Redirecting to homepage `%s'.", s.homepageURL)
		http.Redirect(w, r, s.homepageURL, http.StatusFound)
		return
	}

	// Get state and:
	// 1. Confirm it exists in our memory.
	// 2. Get the original URL associated with it.
	var stateID = r.FormValue("state")
	if len(stateID) == 0 {
		logger.Error("Missing url parameter: state")
		returnMessage(w, http.StatusBadRequest, "Missing url parameter: state")
		return
	}

	// If state is loaded, then it's correct, as it is saved by its id.
	state, err := verifyState(r, w, s.oidcStateStore)
	if err != nil {
		logger.Errorf("Failed to verify state parameter: %v", err)
		returnMessage(w, http.StatusBadRequest, "CSRF check failed."+
			" This may happen if you opened the login form in more than 1"+
			" tabs. Please try to login again.")
		return
	}

	ctx := setTLSContext(r.Context(), s.caBundle)
	// Exchange the authorization code with {access, refresh, id}_token
	oauth2Tokens, err := s.oauth2Config.Exchange(ctx, authCode)
	if err != nil {
		logger.Errorf("Failed to exchange authorization code with token: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Failed to exchange authorization code with token.")
		return
	}

	rawIDToken, ok := oauth2Tokens.Extra("id_token").(string)
	if !ok {
		logger.Error("No id_token field available.")
		returnMessage(w, http.StatusInternalServerError, "No id_token field in OAuth 2.0 token.")
		return
	}

	// Verifying received ID token
	verifier := s.provider.Verifier(&oidc.Config{ClientID: s.oauth2Config.ClientID})
	_, err = verifier.Verify(ctx, rawIDToken)
	if err != nil {
		logger.Errorf("Not able to verify ID token: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Unable to verify ID token.")
		return
	}

	// UserInfo endpoint to get claims
	claims := map[string]interface{}{}
	oidcUserInfo, err := GetUserInfo(ctx, s.provider, s.oauth2Config.TokenSource(ctx, oauth2Tokens))
	if err != nil {
		logger.Errorf("Not able to fetch userinfo: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Not able to fetch userinfo.")
		return
	}

	if err = oidcUserInfo.Claims(&claims); err != nil {
		logger.Errorf("Problem getting userinfo claims: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Not able to fetch userinfo claims.")
		return
	}

	// User is authenticated, create new session.
	session := sessions.NewSession(s.store, userSessionCookie)
	session.Options.MaxAge = s.sessionMaxAgeSeconds
	session.Options.Path = "/"
	// Extra layer of CSRF protection
	session.Options.SameSite = s.sessionSameSite

	userID, ok := claims[s.idTokenOpts.userIDClaim].(string)
	if !ok {
		logger.Errorf("Couldn't find claim `%s' in claims `%v'", s.idTokenOpts.userIDClaim, claims)
		returnMessage(w, http.StatusInternalServerError,
			fmt.Sprintf("Couldn't find userID claim in `%s' in userinfo.", s.idTokenOpts.userIDClaim))
		return
	}

	groups := []string{}
	groupsClaim := claims[s.idTokenOpts.groupsClaim]
	if groupsClaim != nil {
		groups = interfaceSliceToStringSlice(groupsClaim.([]interface{}))
	}

	session.Values[userSessionUserID] = userID
	session.Values[userSessionGroups] = groups
	session.Values[userSessionClaims] = claims
	session.Values[userSessionIDToken] = rawIDToken
	session.Values[userSessionOAuth2Tokens] = oauth2Tokens
	if err := session.Save(r, w); err != nil {
		logger.Errorf("Couldn't create user session: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Error creating user session")
		return
	}

	// Getting the firstVisitedURL from the OIDC state
	var destination = state.FirstVisitedURL
	if s.afterLoginRedirectURL != "" {
		// Redirect to a predefined url from config, add the original url as
		// `next` query parameter.
		afterLoginRedirectURL := mustParseURL(s.afterLoginRedirectURL)
		q := afterLoginRedirectURL.Query()
		q.Set("next", state.FirstVisitedURL)
		afterLoginRedirectURL.RawQuery = q.Encode()
		destination = afterLoginRedirectURL.String()
	}
	logger.WithField("redirectTo", destination).
		Info("Login validated with ID token, redirecting.")
	http.Redirect(w, r, destination, http.StatusFound)
}

// logout is the handler responsible for revoking the user's session.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r, logModuleInfo)

	// Only header auth allowed for this endpoint
	sessionID := getBearerToken(r.Header.Get(s.authHeader))
	if sessionID == "" {
		logger.Errorf("Request doesn't have a session value in header '%s'", s.authHeader)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Revoke user session.
	session, err := sessionFromID(sessionID, s.store)
	if err != nil {
		logger.Errorf("Couldn't get user session: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if session.IsNew {
		logger.Warn("Request doesn't have a valid session.")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	logger = logger.WithField("userid", session.Values[userSessionUserID].(string))

	err = revokeOIDCSession(r.Context(), w, session, s.provider, s.oauth2Config, s.caBundle)
	if err != nil {
		logger.Errorf("Error revoking tokens: %v", err)
		statusCode := http.StatusInternalServerError
		// If the server returned 503, return it as well as the client might want to retry
		if reqErr, ok := errors.Cause(err).(*requestError); ok {
			if reqErr.Response.StatusCode == http.StatusServiceUnavailable {
				statusCode = reqErr.Response.StatusCode
			}
		}
		returnMessage(w, statusCode, "Failed to revoke access/refresh tokens, please try again")
		return
	}

	logger.Info("Successful logout.")
	resp := struct {
		AfterLogoutURL string `json:"afterLogoutURL"`
	}{
		AfterLogoutURL: s.afterLogoutRedirectURL,
	}
	// Return 201 because the logout endpoint is still on the envoy-facing server,
	// meaning that returning a 200 will result in the request being proxied upstream.
	returnJSONMessage(w, http.StatusCreated, resp)
}

// readiness is the handler that checks if the authservice is ready for serving
// requests.
// Currently, it checks if the provider is nil, meaning that the setup hasn't finished yet.
func readiness(isReady *abool.AtomicBool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := http.StatusOK
		if !isReady.IsSet() {
			code = http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
	}
}

// whitelistMiddleware is a middleware that
// - Allows all requests that match the whitelist
// - If the server is ready, forwards requests to be evaluated further
// - If the server is NOT ready, denies requests not permitted by the whitelist
//
// This is necessary because in some topologies, the OIDC Provider and the AuthService
// live are in the same cluster and requests pass through the AuthService.
// Allowing the whitelisted requests before OIDC is configured is necessary for
// the OIDC discovery request to succeed.
func whitelistMiddleware(whitelist []string, isReady *abool.AtomicBool) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := loggerForRequest(r, logModuleInfo)
			// Check whitelist
			for _, prefix := range whitelist {
				if strings.HasPrefix(r.URL.Path, prefix) {
					logger.Infof("URI is whitelisted. Accepted without authorization.")
					returnMessage(w, http.StatusOK, "OK")
					return
				}
			}
			// If server is not ready, return 503.
			if !isReady.IsSet() {
				returnMessage(w, http.StatusServiceUnavailable, "OIDC Setup is not complete yet.")
				return
			}
			// Server ready, continue.
			handler.ServeHTTP(w, r)
		})
	}
}
