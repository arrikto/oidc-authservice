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
	// store is the session store.
	store sessions.Store
	// cookie is the name of the cookie that holds the session value.
	cookie string
	// header is the header to check as an alternative to finding the session
	// value.
	header string
	// strictSessionValidation mode checks the validity of the access token
	// connected with the session on every request.
	strictSessionValidation bool
	// caBundle specifies CAs to trust when talking with the OIDC Provider.
	// Relevant only when strictSessionValidation is enabled.
	caBundle []byte
	// oauth2Config is the config to use when talking with the OIDC Provider.
	// Relevant only when strictSessionValidation is enabled.
	oauth2Config *oauth2.Config
	// provider is the OIDC Provider.
	// Relevant only when strictSessionValidation is enabled.
	provider *oidc.Provider
}

func (sa *sessionAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := loggerForRequest(r)

	// Check header for auth information.
	// Adding it to a cookie to treat both cases uniformly.
	// This is also required by the gorilla/sessions package.
	bearer := getBearerToken(r.Header.Get(sa.header))
	if len(bearer) != 0 {
		r.AddCookie(&http.Cookie{
			Name:   userSessionCookie,
			Value:  bearer,
			Path:   "/",
			MaxAge: 1,
		})
	}

	// Check if user session is valid
	session, err := sa.store.Get(r, sa.cookie)
	if err != nil {
		return nil, false, errors.Wrap(err, "couldn't get user session")
	}
	if session.IsNew {
		return nil, false, nil
	}

	// User is logged in
	if sa.strictSessionValidation {
		ctx := setTLSContext(r.Context(), sa.caBundle)
		token := session.Values[userSessionOAuth2Tokens].(oauth2.Token)
		// TokenSource takes care of automatically renewing the access token.
		_, err := GetUserInfo(ctx, sa.provider, sa.oauth2Config.TokenSource(ctx, &token))
		if err != nil {
			var reqErr *requestError
			if !errors.As(err, &reqErr) {
				return nil, false, errors.Wrap(err, "UserInfo request failed unexpectedly")
			}
			if reqErr.Response.StatusCode != http.StatusUnauthorized {
				return nil, false, errors.Wrapf(err, "UserInfo request with unexpected code '%d'", reqErr.Response.StatusCode)
			}
			// Access token has expired
			logger.Info("UserInfo token has expired")
			session.Options.MaxAge = -1
			if err := sessions.Save(r, httptest.NewRecorder()); err != nil {
				logger.Errorf("Couldn't delete user session: %v", err)
			}
			// Try to revoke token, just in case. According to the spec,
			// trying to revoke an invalid token should return an OK response:
			// https://tools.ietf.org/html/rfc7009#section-2.2
			_revocationEndpoint, err := revocationEndpoint(sa.provider)
			if err != nil {
				logger.Warnf("Error getting provider's revocation_endpoint: %v", err)
			}
			err = revokeTokens(ctx, _revocationEndpoint, &token,
				sa.oauth2Config.ClientID, sa.oauth2Config.ClientSecret)
			if err != nil {
				logger.Errorf("Failed to revoke tokens: %v", err)
			}
			return nil, false, nil
		}
	}

	resp := &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   session.Values[userSessionUserID].(string),
			Groups: session.Values[userSessionGroups].([]string),
		},
	}
	return resp, true, nil
}
