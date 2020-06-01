// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"encoding/gob"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/tevino/abool"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
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
	provider               *oidc.Provider
	oauth2Config           *oauth2.Config
	store                  sessions.Store
	afterLoginRedirectURL  string
	homepageURL            string
	afterLogoutRedirectURL string
	sessionMaxAgeSeconds   int
	userIDOpts
	caBundle []byte
}

func (s *server) authenticate(w http.ResponseWriter, r *http.Request) {

	logger := loggerForRequest(r)

	// Check header for auth information.
	// Adding it to a cookie to treat both cases uniformly.
	// This is also required by the gorilla/sessions package.
	// TODO(yanniszark): change to standard 'Authorization: Bearer <value>' header
	bearer := r.Header.Get("X-Auth-Token")
	if bearer != "" {
		r.AddCookie(&http.Cookie{
			Name:   userSessionCookie,
			Value:  bearer,
			Path:   "/",
			MaxAge: 1,
		})
	}

	// Check if user session is valid
	session, err := s.store.Get(r, userSessionCookie)
	if err != nil {
		logger.Errorf("Couldn't get user session: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Couldn't get user session.")
		return
	}
	// User is logged in
	if !session.IsNew {
		// Add userid header
		userID := session.Values["userid"].(string)
		if userID != "" {
			w.Header().Set(s.userIDOpts.header, s.userIDOpts.prefix+userID)
		}
		if s.userIDOpts.tokenHeader != "" {
			w.Header().Set(s.userIDOpts.tokenHeader, session.Values["idtoken"].(string))
		}
		returnStatus(w, http.StatusOK, "OK")
		return
	}

	// User is NOT logged in.
	// Initiate OIDC Flow with Authorization Request.
	state := newState(r.URL.String())
	id, err := state.save(s.store)
	if err != nil {
		logger.Errorf("Failed to save state in store: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Failed to save state in store.")
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
		returnStatus(w, http.StatusBadRequest, "Missing url parameter: state")
		return
	}

	// If state is loaded, then it's correct, as it is saved by its id.
	state, err := load(s.store, stateID)
	if err != nil {
		logger.Errorf("Failed to retrieve state from store: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Failed to retrieve state.")
	}

	ctx := setTLSContext(r.Context(), s.caBundle)
	// Exchange the authorization code with {access, refresh, id}_token
	oauth2Tokens, err := s.oauth2Config.Exchange(ctx, authCode)
	if err != nil {
		logger.Errorf("Failed to exchange authorization code with token: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Failed to exchange authorization code with token.")
		return
	}

	rawIDToken, ok := oauth2Tokens.Extra("id_token").(string)
	if !ok {
		logger.Error("No id_token field available.")
		returnStatus(w, http.StatusInternalServerError, "No id_token field in OAuth 2.0 token.")
		return
	}

	// Verifying received ID token
	verifier := s.provider.Verifier(&oidc.Config{ClientID: s.oauth2Config.ClientID})
	_, err = verifier.Verify(ctx, rawIDToken)
	if err != nil {
		logger.Errorf("Not able to verify ID token: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Unable to verify ID token.")
		return
	}

	// UserInfo endpoint to get claims
	claims := map[string]interface{}{}
	userInfo, err := s.provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Tokens))
	if err != nil {
		logger.Errorf("Not able to fetch userinfo: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Not able to fetch userinfo.")
		return
	}

	if err = userInfo.Claims(&claims); err != nil {
		logger.Errorf("Problem getting userinfo claims: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Not able to fetch userinfo claims.")
		return
	}

	// User is authenticated, create new session.
	session := sessions.NewSession(s.store, userSessionCookie)
	session.Options.MaxAge = s.sessionMaxAgeSeconds
	session.Options.Path = "/"

	userID, ok := claims[s.userIDOpts.claim].(string)
	if !ok {
		logger.Errorf("Couldn't find claim `%s' in claims `%v'", s.userIDOpts.claim, claims)
		returnStatus(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't find userID claim in `%s' in userinfo.", s.userIDOpts.claim))
		return
	}
	session.Values[userSessionUserID] = userID
	session.Values[userSessionClaims] = claims
	session.Values[userSessionIDToken] = rawIDToken
	session.Values[userSessionOAuth2Tokens] = oauth2Tokens
	if err := session.Save(r, w); err != nil {
		logger.Errorf("Couldn't create user session: %v", err)
		returnStatus(w, http.StatusInternalServerError, "Error creating user session")
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

	// Revoke user session.
	session, err := s.store.Get(r, userSessionCookie)
	if err != nil {
		logger.Errorf("Couldn't get user session: %v", err)
		http.Redirect(w, r, s.afterLogoutRedirectURL, http.StatusSeeOther)
		return
	}
	if session.IsNew {
		logger.Warn("Request doesn't have a valid session.")
		http.Redirect(w, r, s.afterLogoutRedirectURL, http.StatusSeeOther)
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
				if reqErr.StatusCode == http.StatusServiceUnavailable {
					statusCode = reqErr.StatusCode
				}
			}
			returnStatus(w, statusCode, "Failed to revoke access/refresh tokens, please try again")
			return
		}
		logger.WithField("userid", session.Values[userSessionUserID].(string)).Info("Access/Refresh tokens revoked")
	}

	session.Options.MaxAge = -1
	if err := sessions.Save(r, w); err != nil {
		logger.Errorf("Couldn't delete user session: %v", err)
	}
	logger.Info("Successful logout.")
	http.Redirect(w, r, s.afterLogoutRedirectURL, http.StatusSeeOther)
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
					returnStatus(w, http.StatusOK, "OK")
					return
				}
			}
			// If server is not ready, return 503.
			if !isReady.IsSet() {
				returnStatus(w, http.StatusServiceUnavailable, "OIDC Setup is not complete yet.")
				return
			}
			// Server ready, continue.
			handler.ServeHTTP(w, r)
		})
	}
}
