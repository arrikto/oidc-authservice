package authenticators

import (
	"net/http"
	"net/http/httptest"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/arrikto/oidc-authservice/sessions"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type SessionAuthenticator struct {
	// store is the session store.
	Store sessions.Store
	// cookie is the name of the cookie that holds the session value.
	Cookie string
	// header is the header to check as an alternative to finding the session
	// value.
	Header string
	// strictSessionValidation mode checks the validity of the access token
	// connected with the session on every request.
	StrictSessionValidation bool
	// caBundle specifies CAs to trust when talking with the OIDC Provider.
	// Relevant only when strictSessionValidation is enabled.
	CaBundle []byte
	// oauth2Config is the config to use when talking with the OIDC Provider.
	// Relevant only when strictSessionValidation is enabled.
	Oauth2Config *oauth2.Config
	// provider is the OIDC Provider.
	// Relevant only when strictSessionValidation is enabled.
	Provider oidc.Provider
}

func (sa *SessionAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := common.LoggerForRequest(r, "session authenticator")

	// Get session from header or cookie
	session, authMethod, err := sessions.SessionFromRequest(r, sa.Store, sa.Cookie, sa.Header)

	// Check if user session is valid
	if err != nil {
		return nil, false, errors.Wrap(err, "couldn't get user session")
	}
	if session.IsNew {
		logger.Info("Failed to retrieve a valid session")
		return nil, false, nil
	}

	// User is logged in
	if sa.StrictSessionValidation {
		ctx := common.SetTLSContext(r.Context(), sa.CaBundle)
		token := session.Values[sessions.UserSessionOAuth2Tokens].(oauth2.Token)
		// TokenSource takes care of automatically renewing the access token.
		_, err := oidc.GetUserInfo(ctx, sa.Provider, sa.Oauth2Config.TokenSource(ctx, &token))
		if err != nil {
			var reqErr *common.RequestError
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
			err = sessions.RevokeOIDCSession(ctx, httptest.NewRecorder(), session,
				sa.Provider, sa.Oauth2Config, sa.CaBundle)
			if err != nil {
				logger.Errorf("Failed to revoke tokens: %v", err)
			}
			return nil, false, nil
		}
	}

	// Data written at a previous version might not have groups stored, so
	// default to an empty list of strings.
	// TODO: Consolidate all session serialization/deserialization in one place.
	groups, ok := session.Values[sessions.UserSessionGroups].([]string)
	if !ok {
		groups = []string{}
	}

	extra := map[string][]string{"auth-method": {authMethod}}

	resp := &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   session.Values[sessions.UserSessionUserID].(string),
			Groups: groups,
			Extra:  extra,
		},
	}
	return resp, true, nil
}
