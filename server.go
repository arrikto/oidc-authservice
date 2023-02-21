// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/arrikto/oidc-authservice/authenticators"
	"github.com/arrikto/oidc-authservice/common"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/arrikto/oidc-authservice/sessions"
	cache "github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/tevino/abool"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	logModuleInfo = "server"
)

var (
	SessionLogoutPath     = "/logout"
	authenticatorsMapping = []string{
		0: "kubernetes authenticator",
		1: "opaque access token authenticator",
		2: "JWT access token authenticator",
		3: "session authenticator",
		4: "idtoken authenticator",
	}
)

type server struct {
	provider                oidc.Provider
	oauth2Config            *oauth2.Config
	store                   sessions.ClosableStore
	oidcStateStore          sessions.ClosableStore
	bearerUserInfoCache     *cache.Cache
	authenticators          []authenticators.AuthenticatorRequest
	authorizers             []Authorizer
	afterLoginRedirectURL   string
	homepageURL             string
	afterLogoutRedirectURL  string
	verifyAuthURL           string
	sessionMaxAgeSeconds    int
	strictSessionValidation bool

	// Cache Configurations
	cacheEnabled           bool
	cacheExpirationMinutes int

	// Authenticators Configurations
	IDTokenAuthnEnabled     bool
	KubernetesAuthnEnabled  bool
	AccessTokenAuthnEnabled bool
	AccessTokenAuthn        string

	authHeader             string
	idTokenOpts            common.JWTClaimOpts
	upstreamHTTPHeaderOpts common.HTTPHeaderOpts
	userIdTransformer      common.UserIDTransformer
	caBundle               []byte
	sessionSameSite        http.SameSite
}

// authenticate_or_login calls initiates the Authorization Code Flow if the user
// cannot be authenticated with one of the available authenticators.
func (s *server) authenticate_or_login(w http.ResponseWriter, r *http.Request) {
	userInfo, authorized := s.authenticate(w, r, true)
	if !authorized {
		// The user is unauthorized to perform the request
		return
	}
	// The user is successfully authenticated and authorized to perform the
	// request. Proceed with writing the headers on the response and return
	// the `200` HTTP status code.
	for k, v := range common.UserInfoToHeaders(userInfo, &s.upstreamHTTPHeaderOpts, &s.userIdTransformer) {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
	return
}

// authenticate_no_login will not initiate the Authorization Code Flow if the
// user cannot be authenticated. This function will return:
// * HTTP status 204: if the user is authenticated and authorized
// * HTTP status 401 or 403: if not
func (s *server) authenticate_no_login(w http.ResponseWriter, r *http.Request) {
	userInfo, authorized := s.authenticate(w, r, false)
	if !authorized {
		// The user is unauthorized to perform the request
		return
	}
	// The user is successfully authenticated and authorized to perform the
	// request. Proceed with writing the headers on the response and return
	// the `204` HTTP status code.
	for k, v := range common.UserInfoToHeaders(userInfo, &s.upstreamHTTPHeaderOpts, &s.userIdTransformer) {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusNoContent)
	return
}

// authenticate is the core function of AuthService. It implements the following
// steps:
//  1. attempt to authenticate the user who is performing the examined request
//  2. if the user could not be authenticated and promptLogin is false then
//     initiate Authorization Code Flow and skip the next steps
//  3. ensure that the authenticated user is authorized to access the requested
//     resource, if they are not then deny the access and skip step 4
//  4. update the headers of the request with the retrieved userInfo and allow the
//     request
//
// We are calling this function from two wrappers:
// * authenticate_no_login(), this is the handler of the /verify endpoint
// * authenticate_or_login()
func (s *server) authenticate(w http.ResponseWriter, r *http.Request, promptLogin bool) (user.Info, bool) {

	logger := common.RequestLogger(r, logModuleInfo)
	logger.Info("Authenticating request...")

	// Try each one of the available enabled authenticators, if none of them
	// achieves to authenticate the request then userInfo will be nil and
	// Authorization Code Flow will begin.
	userInfo, authorized := s.tryAuthenticators(w, r, promptLogin)
	if !authorized {
		return nil, false
	}

	// Preliminary check for the /verify endpoint
	// if the user is not authenticated return 401
	if userInfo == nil {
		// Preliminary check for the /verify endpoint
		// if the user is not authenticated return 401
		if !promptLogin {
			common.ReturnMessage(w, http.StatusUnauthorized, "Unauthorized")
			return nil, false
		}

		logger.Infof("Failed to authenticate using authenticators. Initiating OIDC Authorization Code flow...")
		// TODO: Detect "X-Requested-With" header and return 401
		s.authCodeFlowAuthenticationRequest(w, r)
		return nil, false
	}

	logger = logger.WithField("user", userInfo)
	logger.Info("Authorizing request...")

	// Ensure that all authorizers allow the access to the requested resource
	authorized = s.authorized(w, r, userInfo)
	if !authorized {
		return nil, false
	}

	return userInfo, true
}

// tryAuthenticators will iterate over the available enabled authenticators.
// If one of them manages to authenticate the user who is making the requester
// then it will return their user Info and all the other authenticator will be
// skipped.
func (s *server) tryAuthenticators(w http.ResponseWriter, r *http.Request, promptLogin bool) (user.Info, bool) {
	logger := common.RequestLogger(r, logModuleInfo)

	var userInfo user.Info
	for i, auth := range s.authenticators {
		if !s.enabledAuthenticator(authenticatorsMapping[i]) {
			continue
		}

		var cacheKey string

		if s.cacheEnabled {
			// If caching is enabled, and the current authenticator
			// implements the cacheable interface then try to
			// retrieve the UserInfo from cache and the cacheKey for
			// this cache entry.
			userInfo, cacheKey = s.getCachedUser(auth, r)

			if userInfo != nil {
				logger.Infof("Successfully authenticated request using the cache.")
				logger.Debugf("UserInfo: %+v", userInfo)
				return userInfo, true
			}
		}

		logger.Debugf("%s starting...", strings.Title(authenticatorsMapping[i]))
		resp, found, err := auth.AuthenticateRequest(r)
		if err != nil {
			logger.Errorf("Error authenticating request using %s: %v", authenticatorsMapping[i], err)
			// If we get a login expired error, it means the
			// authenticator recognised a valid authentication method
			// which has expired
			var expiredErr *common.LoginExpiredError
			if errors.As(err, &expiredErr) {
				common.ReturnMessage(w, http.StatusUnauthorized, expiredErr.Error())
				return nil, false
			}

			// If AuthService encountered an authenticator-specific
			// error, then no other authentication methods will be
			// tested.
			var authnError *common.AuthenticatorSpecificError
			if errors.As(err, &authnError) {
				common.ReturnMessage(w, http.StatusUnauthorized, authnError.Error())
				return nil, false
			}

		}
		if found {
			logger.Infof("Successfully authenticated request using %s", authenticatorsMapping[i])
			userInfo = resp.User
			logger.Debugf("UserInfo: %+v", userInfo)

			if s.cacheEnabled && cacheKey != "" && promptLogin {
				// If cache is enabled and the current authenticator is Cacheable, store the UserInfo to cache.
				logger.Debugf("Caching authenticated UserInfo...")
				s.bearerUserInfoCache.Set(cacheKey, userInfo, time.Duration(s.cacheExpirationMinutes)*time.Minute)
			}
			return userInfo, true
		}
	}
	return nil, true
}

// authorize tries out all of the available authorizers. If at least one of them
// does not allow the user to make the request then AuthService denies the access
// to this resource.
func (s *server) authorized(w http.ResponseWriter, r *http.Request, userInfo user.Info) bool {
	logger := common.RequestLogger(r, logModuleInfo)

	for _, authz := range s.authorizers {
		allowed, reason, err := authz.Authorize(r, userInfo)
		if err != nil {
			logger.Errorf("Error authorizing request using authorizer %T: %v", authz, err)
			w.WriteHeader(http.StatusForbidden)
			return false
		}
		// If the request is not allowed, try to revoke the user's session.
		// TODO: Only revoke if the authenticator that provided the identity is
		// the session authenticator.
		if !allowed {
			logger.Infof("Authorizer '%T' denied the request with reason: '%s'", authz, reason)
			session, _, err := sessions.SessionFromRequest(r, s.store, sessions.UserSessionCookie, s.authHeader)
			if err != nil {
				logger.Errorf("Error getting session for request: %v", err)
			}
			if !session.IsNew {
				err = sessions.RevokeOIDCSession(r.Context(), w, session, s.provider, s.oauth2Config, s.caBundle)
				if err != nil {
					logger.Errorf("Failed to revoke session after authorization fail: %v", err)
				}
			}
			// TODO: Move this to the web server and make it prettier
			msg := fmt.Sprintf("User '%s' failed authorization with reason: %s. "+
				"Click <a href='%s'> here</a> to login again.", userInfo.GetName(),
				reason, s.homepageURL)

			common.ReturnHTML(w, http.StatusForbidden, msg)
			return false
		}
	}

	return true
}

// getCachedUser returns:
// * the UserInfo
// * the cacheKey
// if there is an entry in the cache for the examined user.
// Otherwise, it returns an empty string for the cacheKey and nil respectively.
func (s *server) getCachedUser(auth authenticators.AuthenticatorRequest, r *http.Request) (user.Info, string) {
	logger := common.RequestLogger(r, logModuleInfo)

	// If the cache is enabled, check if the current authenticator implements the Cacheable interface.
	cacheable := reflect.TypeOf((*authenticators.Cacheable)(nil)).Elem()
	isCacheable := reflect.TypeOf(auth).Implements(cacheable)

	if isCacheable {
		// Store the key that we are going to use for caching UserDetails.
		// We store it before the authentication, because the authenticators may mutate the request object.
		logger.Debugf("Retrieving the cache key...")
		cacheableAuthenticator := reflect.ValueOf(auth).Interface().(authenticators.Cacheable)
		cacheKey := cacheableAuthenticator.GetCacheKey(r)

		if cacheKey != "" {
			cachedUserInfo, found := s.bearerUserInfoCache.Get(cacheKey)
			if found {
				userInfo := cachedUserInfo.(user.Info)
				logger.Debugf("Found Cached UserInfo: %+v", userInfo)
				return userInfo, cacheKey
			}
			return nil, cacheKey
		}
	}

	logger.Debug("The UserInfo is not cached.")
	return nil, ""
}

// authCodeFlowAuthenticationRequest initiates an OIDC Authorization Code flow
func (s *server) authCodeFlowAuthenticationRequest(w http.ResponseWriter, r *http.Request) {
	logger := common.RequestLogger(r, logModuleInfo)

	// Initiate OIDC Flow with Authorization Request.
	state, err := sessions.CreateState(r, w, s.oidcStateStore)
	if err != nil {
		logger.Errorf("Failed to save state in store: %v", err)
		common.ReturnMessage(w, http.StatusInternalServerError, "Failed to save state in store.")
		return
	}

	http.Redirect(w, r, s.oauth2Config.AuthCodeURL(state), http.StatusFound)
}

// callback is the handler responsible for exchanging the auth_code and retrieving an id_token.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {

	logger := common.RequestLogger(r, logModuleInfo)

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
		common.ReturnMessage(w, http.StatusBadRequest, "Missing url parameter: state")
		return
	}

	// If state is loaded, then it's correct, as it is saved by its id.
	state, err := sessions.VerifyState(r, w, s.oidcStateStore)
	if err != nil {
		logger.Errorf("Failed to verify state parameter: %v", err)
		common.ReturnMessage(w, http.StatusBadRequest, "CSRF check failed."+
			" This may happen if you opened the login form in more than 1"+
			" tabs. Please try to login again.")
		return
	}

	ctx := common.SetTLSContext(r.Context(), s.caBundle)
	// Exchange the authorization code with {access, refresh, id}_token
	oauth2Tokens, err := s.oauth2Config.Exchange(ctx, authCode)
	if err != nil {
		logger.Errorf("Failed to exchange authorization code with token: %v", err)
		common.ReturnMessage(w, http.StatusInternalServerError, "Failed to exchange authorization code with token.")
		return
	}

	rawIDToken, ok := oauth2Tokens.Extra("id_token").(string)
	if !ok {
		logger.Error("No id_token field available.")
		common.ReturnMessage(w, http.StatusInternalServerError, "No id_token field in OAuth 2.0 token.")
		return
	}

	// Verifying received ID token
	verifier := s.provider.Verifier(
		oidc.NewConfig(s.oauth2Config.ClientID))
	_, err = verifier.Verify(ctx, rawIDToken)
	if err != nil {
		logger.Errorf("Not able to verify ID token: %v", err)
		common.ReturnMessage(w, http.StatusInternalServerError, "Unable to verify ID token.")
		return
	}

	// UserInfo endpoint to get claims
	claims := map[string]interface{}{}

	newTokens, _, err := oidc.TokenSource(ctx, s.oauth2Config, oauth2Tokens)
	userInfo, err := oidc.GetUserInfo(ctx, s.provider, newTokens)
	if err != nil {
		logger.Errorf("Not able to fetch userinfo: %v", err)
		common.ReturnMessage(w, http.StatusInternalServerError, "Not able to fetch userinfo.")
		return
	}

	if err = userInfo.Claims(&claims); err != nil {
		logger.Errorf("Problem getting userinfo claims: %v", err)
		common.ReturnMessage(w, http.StatusInternalServerError, "Not able to fetch userinfo claims.")
		return
	}

	// User is authenticated, create new session.
	session := sessions.NewSession(s.store, sessions.UserSessionCookie)
	session.Options.MaxAge = s.sessionMaxAgeSeconds
	session.Options.Path = "/"
	// Extra layer of CSRF protection
	session.Options.SameSite = s.sessionSameSite

	userID, ok := claims[s.idTokenOpts.UserIDClaim].(string)
	if !ok {
		logger.Errorf("Couldn't find claim `%s' in claims `%v'", s.idTokenOpts.UserIDClaim, claims)
		common.ReturnMessage(w, http.StatusInternalServerError,
			fmt.Sprintf("Couldn't find userID claim in `%s' in userinfo.", s.idTokenOpts.UserIDClaim))
		return
	}

	groups := []string{}
	groupsClaim := claims[s.idTokenOpts.GroupsClaim]
	if groupsClaim != nil {
		groups = common.InterfaceSliceToStringSlice(groupsClaim.([]interface{}))
	}

	session.Values[sessions.UserSessionUserID] = userID
	session.Values[sessions.UserSessionGroups] = groups
	session.Values[sessions.UserSessionClaims] = claims
	session.Values[sessions.UserSessionIDToken] = rawIDToken
	session.Values[sessions.UserSessionOAuth2Tokens] = oauth2Tokens
	if err := session.Save(r, w); err != nil {
		logger.Errorf("Couldn't create user session: %v", err)
		common.ReturnMessage(w, http.StatusInternalServerError, "Error creating user session")
		return
	}

	// Getting the firstVisitedURL from the OIDC state
	var destination = state.FirstVisitedURL
	if s.afterLoginRedirectURL != "" {
		// Redirect to a predefined url from config, add the original url as
		// `next` query parameter.
		afterLoginRedirectURL := common.MustParseURL(s.afterLoginRedirectURL)
		q := afterLoginRedirectURL.Query()
		q.Set("next", state.FirstVisitedURL)
		afterLoginRedirectURL.RawQuery = q.Encode()
		destination = afterLoginRedirectURL.String()
	}
	logger.WithField("redirectTo", destination).
		Info("Login validated with ID token, redirecting.")
	http.Redirect(w, r, destination, http.StatusFound)
}

// enabledAuthenticator indicates if the examined authenticator is enabled.
func (s *server) enabledAuthenticator(authenticator string) bool {
	if authenticator == "kubernetes authenticator" && s.KubernetesAuthnEnabled {
		return true
	}
	if s.AccessTokenAuthnEnabled {
		if authenticator == "opaque access token authenticator" && s.AccessTokenAuthn == "opaque" {
			return true
		}
		if authenticator == "JWT access token authenticator" && s.AccessTokenAuthn == "jwt" {
			return true
		}
	}
	if authenticator == "session authenticator" {
		return true
	}
	if authenticator == "idtoken authenticator" && s.IDTokenAuthnEnabled {
		return true
	}
	return false
}

// logout is the handler responsible for revoking the user's session.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {

	logger := common.RequestLogger(r, logModuleInfo)

	// Only header auth allowed for this endpoint
	sessionID := common.GetBearerToken(r.Header.Get(s.authHeader))
	if sessionID == "" {
		logger.Errorf("Request doesn't have a session value in header '%s'", s.authHeader)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Revoke user session.
	session, err := sessions.SessionFromID(sessionID, s.store)
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
	logger = logger.WithField("userid", session.Values[sessions.UserSessionUserID].(string))

	err = sessions.RevokeOIDCSession(r.Context(), w, session, s.provider, s.oauth2Config, s.caBundle)
	if err != nil {
		logger.Errorf("Error revoking tokens: %v", err)
		statusCode := http.StatusInternalServerError
		// If the server returned 503, return it as well as the client might want to retry
		if reqErr, ok := errors.Cause(err).(*common.RequestError); ok {
			if reqErr.Response.StatusCode == http.StatusServiceUnavailable {
				statusCode = reqErr.Response.StatusCode
			}
		}
		common.ReturnMessage(w, statusCode, "Failed to revoke access/refresh tokens, please try again")
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
	common.ReturnJSONMessage(w, http.StatusCreated, resp)
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
func (s *server) whitelistMiddleware(whitelist []string, isReady *abool.AtomicBool, verify bool) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := common.RequestLogger(r, logModuleInfo)

			path := r.URL.Path
			// If called by the `/authservice/verify` router then
			// first trim the verifyAuthURL prefix and then examine
			// if the remaining path is whitelisted.
			if verify {
				path = strings.TrimPrefix(r.URL.Path, s.verifyAuthURL)
			}
			// Check whitelist
			for _, prefix := range whitelist {
				if strings.HasPrefix(path, prefix) {
					logger.Debugf("URI is whitelisted. Accepted without authorization.")
					if verify {
						w.WriteHeader(http.StatusNoContent)
					} else {
						common.ReturnMessage(w, http.StatusOK, "OK")
					}
					return
				}
			}
			// If server is not ready, return 503.
			if !isReady.IsSet() {
				common.ReturnMessage(w, http.StatusServiceUnavailable, "OIDC Setup is not complete yet.")
				return
			}
			// Server ready, continue.
			handler.ServeHTTP(w, r)
		})
	}
}
