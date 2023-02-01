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
	logger := loggerForRequest(r, "session authenticator")

	// Get session from header or cookie
	session, authMethod, err := sessionFromRequest(r, sa.store, sa.cookie, sa.header)

	// Check if user session is valid
	if err != nil {
		return nil, false, errors.Wrap(err, "couldn't get user session")
	}
	if session.IsNew {
		logger.Info("Failed to retrieve a valid session")
		return nil, false, nil
	}

	// User is logged in
	if sa.strictSessionValidation {
		ctx := setTLSContext(r.Context(), sa.caBundle)
		token := session.Values[userSessionOAuth2Tokens].(oauth2.Token)
		// TokenSource takes care of automatically renewing the access token.
		logger.Infof("ATHINAPL-token: %+v", token)
		_, err := GetUserInfo(ctx, sa.provider, sa.oauth2Config.TokenSource(ctx, &token), logger)
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
			// XXX: With the current abstraction, an authenticator doesn't have
			// access to the ResponseWriter and thus can't set a cookie. This
			// means that the cookie will remain at the user's browser but it
			// will be replaced after the user logs in again.
			err = revokeOIDCSession(ctx, httptest.NewRecorder(), session,
				sa.provider, sa.oauth2Config, sa.caBundle)
			if err != nil {
				logger.Errorf("Failed to revoke tokens: %v", err)
			}
			return nil, false, nil
		}
	}

	// Data written at a previous version might not have groups stored, so
	// default to an empty list of strings.
	// TODO: Consolidate all session serialization/deserialization in one place.
	groups, ok := session.Values[userSessionGroups].([]string)
	if !ok {
		groups = []string{}
	}

	extra := map[string][]string{"auth-method": {authMethod}}

	resp := &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   session.Values[userSessionUserID].(string),
			Groups: groups,
			Extra:  extra,
		},
	}
	return resp, true, nil
}
