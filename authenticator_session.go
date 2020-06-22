package main

import (
	"net/http"
	"net/http/httptest"

	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type sessionAuthenticator struct {
	store                   sessions.Store
	cookie                  string
	header                  string
	strictSessionValidation bool
	caBundle                []byte
	provider                *oidc.Provider
}

func (sessauth *sessionAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := loggerForRequest(r)

	// Check header for auth information.
	// Adding it to a cookie to treat both cases uniformly.
	// This is also required by the gorilla/sessions package.
	bearer := getBearerToken(r.Header.Get(sessauth.header))
	if len(bearer) != 0 {
		r.AddCookie(&http.Cookie{
			Name:   userSessionCookie,
			Value:  bearer,
			Path:   "/",
			MaxAge: 1,
		})
	}

	// Check if user session is valid
	session, err := sessauth.store.Get(r, sessauth.cookie)
	if err != nil {
		return nil, false, errors.Wrap(err, "couldn't get user session")
	}
	if session.IsNew {
		return nil, false, nil
	}

	// User is logged in
	if sessauth.strictSessionValidation {
		ctx := setTLSContext(r.Context(), sessauth.caBundle)
		oauth2Tokens := session.Values[userSessionOAuth2Tokens].(oauth2.Token)
		_, err := sessauth.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2Tokens))
		if err != nil {
			logger.Warnf("UserInfo request failed, assuming expired token: %v", err)
			session.Options.MaxAge = -1
			if err := sessions.Save(r, &httptest.ResponseRecorder{}); err != nil {
				return nil, false, errors.Wrap(err, "couldn't delete user session")
			}
		}
	}

	resp := &authenticator.Response{
		User: &user.DefaultInfo{
			Name: session.Values[userSessionUserID].(string),
		},
	}
	return resp, true, nil
}
