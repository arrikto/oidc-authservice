package authenticator

import (
	"net/http"
	"net/http/httptest"

	"github.com/arrikto/oidc-authservice/logger"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/arrikto/oidc-authservice/svc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type sessionAuthenticator struct {
	// store is the session store.
	store oidc.SessionStore
	// tokenHeader is the header that is set by the authenticator containing
	// the user id token
	tokenHeader string
	// tokenScheme is the authorization scheme used for sending the user id token.
	// e.g. Bearer, Basic
	tokenScheme string
	// strictSessionValidation mode checks the validity of the access token
	// connected with the session on every request.
	strictSessionValidation bool
	// tlsCfg manages the bundles for CAs to trust when talking with the
	// OIDC Provider. Relevant only when strictSessionValidation is enabled.
	tlsCfg svc.TlsConfig
	// sm is responsible for managing OIDC sessions
	sm oidc.SessionManager
}

func NewSessionAuthenticator(
	store oidc.SessionStore,
	tokenHeader, tokenScheme string,
	strictSessionValidation bool,
	tlsCfg svc.TlsConfig,
	sessionManager oidc.SessionManager) Authenticator {

	return &sessionAuthenticator{
		store:                   store,
		tokenHeader:             tokenHeader,
		tokenScheme:             tokenScheme,
		strictSessionValidation: strictSessionValidation,
		tlsCfg:                  tlsCfg,
		sm:                      sessionManager,
	}
}

func (sa *sessionAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*User, error) {
	logger := logger.ForRequest(r)
	logger.Info("Attempting HTTP session authentication")

	// Get session from header or cookie
	session, err := sa.store.SessionFromRequest(r)

	// Check if user session is valid
	if err != nil {
		return nil, errors.Wrap(err, "couldn't get user session")
	}
	if session.IsNew {
		return nil, nil
	}

	// User is logged in
	if sa.strictSessionValidation {
		ctx := sa.tlsCfg.Context(r.Context())
		token := session.Values[oidc.UserSessionOAuth2Tokens].(oauth2.Token)
		_, err := sa.sm.GetUserInfo(ctx, &token)
		if err != nil {
			var reqErr *svc.RequestError
			if !errors.As(err, &reqErr) {
				return nil, errors.Wrap(err, "UserInfo request failed unexpectedly")
			}
			if reqErr.Response.StatusCode != http.StatusUnauthorized {
				return nil, errors.Wrapf(err, "UserInfo request with unexpected code '%d'", reqErr.Response.StatusCode)
			}
			// Access token has expired
			logger.Info("UserInfo token has expired")
			// XXX: With the current abstraction, an authenticator doesn't have
			// access to the ResponseWriter and thus can't set a cookie. This
			// means that the cookie will remain at the user's browser but it
			// will be replaced after the user logs in again.
			err = sa.sm.RevokeSession(ctx, httptest.NewRecorder(), session)
			if err != nil {
				logger.Errorf("Failed to revoke tokens: %v", err)
			}
			return nil, nil
		}
	}

	// Data written at a previous version might not have groups stored, so
	// default to an empty list of strings.
	// TODO: Consolidate all session serialization/deserialization in one place.
	groups, ok := session.Values[oidc.UserSessionGroups].([]string)
	if !ok {
		groups = []string{}
	}

	// set auth header with user token
	idHeader := session.Values[oidc.UserSessionIDToken].(string)
	// prepend authorization scheme if one is specified
	if sa.tokenScheme != "" {
		idHeader = sa.tokenScheme + " " + idHeader
	}
	w.Header().Set(sa.tokenHeader, idHeader)

	resp := &User{
		Name:   session.Values[oidc.UserSessionUserID].(string),
		Groups: groups,
	}
	return resp, nil
}
