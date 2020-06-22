// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/tevino/abool"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	userSessionCookie       = "authservice_session"
	userSessionUserID       = "userid"
	userSessionClaims       = "claims"
	userSessionIDToken      = "idtoken"
	userSessionOAuth2Tokens = "oauth2tokens"
)

var (
	OIDCCallbackPath  = "/oidc/callback"
	SessionLogoutPath = "/logout"
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
	authenticators          []authenticator.Request
	afterLoginRedirectURL   string
	homepageURL             string
	afterLogoutRedirectURL  string
	sessionMaxAgeSeconds    int
	strictSessionValidation bool
	authHeader              string
	userIDOpts
	caBundle []byte
}

func (s *server) authenticate(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r)
	logger.Info("Authenticating request...")

	var userInfo user.Info
	for i, auth := range s.authenticators {
		resp, found, err := auth.AuthenticateRequest(r)
		if err != nil {
			logger.Errorf("Error authenticating request using authenticator %d: %v", i, err)
			// If we get a login expired error, it means the authenticator
			// recognised a valid authentication method which has expired
			var expiredErr *loginExpiredError
			if errors.As(err, &expiredErr) {
				returnMessage(w, http.StatusUnauthorized, expiredErr.Error())
				return
			}
		}
		if found {
			userInfo = resp.User
			logger.Infof("UserInfo: %+v", userInfo)
			break
		}
	}
	if userInfo == nil {
		logger.Infof("Failed to authenticate using authenticators. Initiating OIDC Authorization Code flow...")
		// TODO: Detect "X-Requested-With" header and return 401
		s.authCodeFlowAuthenticationRequest(w, r)
		return
	}
	for k, v := range userInfoToHeaders(userInfo, s.userIDOpts) {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
	return
}

// authCodeFlowAuthenticationRequest initiates an OIDC Authorization Code flow
func (s *server) authCodeFlowAuthenticationRequest(w http.ResponseWriter, r *http.Request) {
	logger := loggerForRequest(r)

	// Initiate OIDC Flow with Authorization Request.
	state := newState(r.URL.String())
	id, err := state.save(s.store)
	if err != nil {
		logger.Errorf("Failed to save state in store: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Failed to save state in store.")
		return
	}

	http.Redirect(w, r, s.oauth2Config.AuthCodeURL(id), http.StatusFound)
}

// callback is the handler responsible for exchanging the auth_code and retrieving an id_token.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r)

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
	state, err := load(s.store, stateID)
	if err != nil {
		logger.Errorf("Failed to retrieve state from store: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Failed to retrieve state.")
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
	userInfo, err := GetUserInfo(ctx, s.provider, s.oauth2Config.TokenSource(ctx, oauth2Tokens))
	if err != nil {
		logger.Errorf("Not able to fetch userinfo: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Not able to fetch userinfo.")
		return
	}

	if err = userInfo.Claims(&claims); err != nil {
		logger.Errorf("Problem getting userinfo claims: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Not able to fetch userinfo claims.")
		return
	}

	// User is authenticated, create new session.
	session := sessions.NewSession(s.store, userSessionCookie)
	session.Options.MaxAge = s.sessionMaxAgeSeconds
	session.Options.Path = "/"
	// Extra layer of CSRF protection
	session.Options.SameSite = http.SameSiteStrictMode

	userID, ok := claims[s.userIDOpts.claim].(string)
	if !ok {
		logger.Errorf("Couldn't find claim `%s' in claims `%v'", s.userIDOpts.claim, claims)
		returnMessage(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't find userID claim in `%s' in userinfo.", s.userIDOpts.claim))
		return
	}
	session.Values[userSessionUserID] = userID
	session.Values[userSessionClaims] = claims
	session.Values[userSessionIDToken] = rawIDToken
	session.Values[userSessionOAuth2Tokens] = oauth2Tokens
	if err := session.Save(r, w); err != nil {
		logger.Errorf("Couldn't create user session: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Error creating user session")
		return
	}

	logger.Info("Login validated with ID token, redirecting.")

	// Getting original destination from DB with state
	var destination = state.origURL
	if s.afterLoginRedirectURL != "" {
		destination = s.afterLoginRedirectURL
	}

	http.Redirect(w, r, destination, http.StatusFound)
}

// logout is the handler responsible for revoking the user's session.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r)

	// Clear all cookies, only header auth allowed for this endpoint
	r.Header.Set("Cookie", "")
	bearer := getBearerToken(r.Header.Get(s.authHeader))
	if len(bearer) != 0 {
		r.AddCookie(&http.Cookie{
			Name:   userSessionCookie,
			Value:  bearer,
			Path:   "/",
			MaxAge: 1,
		})
	}

	// Revoke user session.
	session, err := s.store.Get(r, userSessionCookie)
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

	// Check if the provider has a revocation_endpoint
	_revocationEndpoint, err := revocationEndpoint(s.provider)
	if err != nil {
		logger.Warnf("Error getting provider's revocation_endpoint: %v", err)
	} else {
		ctx := setTLSContext(r.Context(), s.caBundle)
		token := session.Values[userSessionOAuth2Tokens].(oauth2.Token)
		err := revokeTokens(ctx, _revocationEndpoint, &token, s.oauth2Config.ClientID, s.oauth2Config.ClientSecret)
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
		logger.WithField("userid", session.Values[userSessionUserID].(string)).Info("Access/Refresh tokens revoked")
	}

	session.Options.MaxAge = -1
	if err := sessions.Save(r, w); err != nil {
		logger.Errorf("Couldn't delete user session: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Couldn't delete user session")
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
			logger := loggerForRequest(r)
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
