// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/arrikto/oidc-authservice/authenticator"
	"github.com/arrikto/oidc-authservice/authorizer"
	"github.com/arrikto/oidc-authservice/logger"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/arrikto/oidc-authservice/svc"
	"github.com/pkg/errors"
	"github.com/tevino/abool"
)

var (
	OIDCCallbackPath  = "/oidc/callback"
	SessionLogoutPath = "/logout"
)

type server struct {
	sessionStore           oidc.SessionStore
	oidcStateStore         oidc.OidcStateStore
	authenticators         []authenticator.Authenticator
	authorizers            []authorizer.Authorizer
	afterLoginRedirectURL  string
	homepageURL            string
	afterLogoutRedirectURL string
	userHeaderHelper       *userHeaderHelper
	userIdTransformer      UserIDTransformer
	caBundle               []byte
	sessionManager         oidc.SessionManager
	tlsCfg                 svc.TlsConfig
	newState               oidc.StateFunc
}

// httpHeaderOpts specifies the location of the user's identity inside HTTP
// headers.
type httpHeaderOpts struct {
	userIDHeader string
	userIDPrefix string
	groupsHeader string
}

type userHeaderFn func(user *authenticator.User) string

type userHeaderHelper struct {
	headers map[string]userHeaderFn
}

func newUserHeaderHelper(opts httpHeaderOpts, transformer *UserIDTransformer) *userHeaderHelper {
	helper := userHeaderHelper{headers: make(map[string]userHeaderFn)}

	if opts.userIDHeader != "" {
		helper.headers[opts.userIDHeader] = func(u *authenticator.User) string {
			return opts.userIDPrefix + transformer.Transform(u.Name)
		}
	}

	if opts.groupsHeader != "" {
		helper.headers[opts.groupsHeader] = func(u *authenticator.User) string {
			return strings.Join(u.Groups, ",")
		}
	}
	return &helper
}

func (u *userHeaderHelper) AddHeaders(w http.ResponseWriter, user *authenticator.User) {
	for header, valueFn := range u.headers {
		w.Header().Add(header, valueFn(user))
	}
}

func (s *server) authenticate(w http.ResponseWriter, r *http.Request) {
	logger := logger.ForRequest(r)
	logger.Info("Authenticating request...")

	// Enforce no caching on the browser side.
	w.Header().Add("Cache-Control", "private, max-age=0, no-cache, no-store")

	var user *authenticator.User
	for i, auth := range s.authenticators {
		resp, err := auth.Authenticate(w, r)

		if err != nil {
			logger.Errorf("Error authenticating request using authenticator %d: %v", i, err)
			// If the authenticator returns an error, this indicates that
			// the request contained a valid authentication method which has expired
			var expiredErr *svc.LoginExpiredError
			if errors.As(err, &expiredErr) {
				returnMessage(w, http.StatusUnauthorized, expiredErr.Error())
				return
			}
		}
		// Check if user was set/found
		if resp != nil {
			user = resp
			// TODO do not print userInfo.IDToken
			// solve this by either making it a hidden field,
			// only logging name + groups
			// writing the token header inside of the authenticator -- prob best
			logger.Infof("UserInfo: %+v", user)
			break
		}
	}
	if user == nil {
		logger.Infof("Failed to authenticate using authenticators. Initiating OIDC Authorization Code flow...")
		// TODO: Detect "X-Requested-With" header and return 401
		s.authCodeFlowAuthenticationRequest(w, r)
		return
	}

	logger = logger.WithField("user", user)
	logger.Info("Authorizing request...")

	for i, authz := range s.authorizers {
		allowed, reason, err := authz.Authorize(r, user)
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
			session, err := s.sessionStore.SessionFromRequest(r)
			if err != nil {
				logger.Errorf("Error getting session for request: %v", err)
			}
			if !session.IsNew {
				err := s.sessionManager.RevokeSession(
					s.tlsCfg.Context(r.Context()), w, session)
				if err != nil {
					logger.Errorf("Failed to revoke session after authorization fail: %v", err)
				}
			}
			// TODO: Move this to the web server and make it prettier
			msg := fmt.Sprintf("User '%s' failed authorization with reason: %s. ", user.Name, reason)

			returnHTML(w, http.StatusForbidden, msg)
			return
		}
	}

	s.userHeaderHelper.AddHeaders(w, user)

	w.WriteHeader(http.StatusOK)
	return
}

// authCodeFlowAuthenticationRequest initiates an OIDC Authorization Code flow
func (s *server) authCodeFlowAuthenticationRequest(w http.ResponseWriter, r *http.Request) {
	logger := logger.ForRequest(r)

	// Initiate OIDC Flow with Authorization Request.
	// create state parameter from request and store it in cookie with the session key
	if err := s.oidcStateStore.CreateState(r, w, s.newState); err != nil {
		logger.Errorf("Failed to save state in store: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Failed to save state in store.")
		return
	}

	// Cookie is persisted in ResponseWriter, make a request to parse it.
	tempReq := &http.Request{Header: make(http.Header)}
	tempReq.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	c, err := tempReq.Cookie(oidc.OidcStateCookie)

	if err != nil {
		logger.Errorf("Failed to save state in store: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Failed to save state in store.")
		return
	}
	w.Header().Add("X-OIDC-Device-Flow-Url", s.sessionManager.DeviceAuthURL())
	http.Redirect(w, r, s.sessionManager.AuthCodeURL(c.Value), http.StatusFound)
}

// callback is the handler responsible for exchanging the auth_code and retrieving an id_token.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {

	logger := logger.ForRequest(r)

	// Enforce no caching on the browser side.
	w.Header().Add("Cache-Control", "private, max-age=0, no-cache, no-store")

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
	state, err := s.oidcStateStore.Verify(r, w)
	if err != nil {
		logger.Errorf("Failed to verify state parameter: %v", err)
		returnMessage(w, http.StatusBadRequest, "CSRF check failed."+
			" This may happen if you opened the login form in more than 1"+
			" tabs. Please try to login again.")
		return
	}

	ctx := s.tlsCfg.Context(r.Context())
	oauth2Tokens, err := s.sessionManager.ExchangeCode(ctx, authCode)
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
	_, err = s.sessionManager.Verify(ctx, rawIDToken, "")
	if err != nil {
		logger.Errorf("Not able to verify ID token: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Unable to verify ID token.")
		return
	}

	// UserInfo endpoint to get claims
	oidcUserInfo, err := s.sessionManager.GetUserInfo(ctx, oauth2Tokens)
	if err != nil {
		logger.Errorf("Not able to fetch userinfo: %v", err)
		returnMessage(w, http.StatusInternalServerError, "Not able to fetch userinfo.")
		return
	}

	// User is authenticated, create new session.
	_, err = s.sessionStore.NewSession(r, w, oidcUserInfo, rawIDToken, oauth2Tokens)
	if err != nil {
		logger.Errorf("failed to create session: %v", err)
		returnMessage(w, http.StatusInternalServerError, "failed to create session")
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
	logger := logger.ForRequest(r)

	session, err := s.sessionStore.SessionForLogout(r)
	if err != nil {
		logger.Errorf(err.Error())
		var serr oidc.SessionError
		if errors.As(err, &serr) && serr.Code == oidc.SessionErrorUnauth {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	logger = logger.WithField("userid", session.Values[oidc.UserSessionUserID].(string))
	ctx := s.tlsCfg.Context(r.Context())

	err = s.sessionManager.RevokeSession(ctx, w, session)
	if err != nil {
		logger.Errorf("Error revoking tokens: %v", err)
		statusCode := http.StatusInternalServerError
		// If the server returned 503, return it as well as the client might want to retry
		if reqErr, ok := errors.Cause(err).(*svc.RequestError); ok {
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
			logger := logger.ForRequest(r)
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
