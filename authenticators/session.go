package authenticators

import (
	"net/http"
	"net/http/httptest"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/arrikto/oidc-authservice/sessions"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type SessionAuthenticator struct {
	// store is the session store.
	Store sessions.Store
	// cookie is the name of the cookie that holds the session value.
	Cookie string
	// TokenHeader is the header that is set by the authenticator containing
	// the user id token
	TokenHeader string
	// TokenScheme is the authorization scheme used for sending the user id token.
	// e.g. Bearer, Basic
	TokenScheme string
	// strictSessionValidation mode checks the validity of the access token
	// connected with the session on every request.
	StrictSessionValidation bool
	// tlsCfg manages the bundles for CAs to trust when talking with the
	// OIDC Provider. Relevant only when strictSessionValidation is enabled.
	TLSConfig common.TlsConfig
	// SessionManager is responsible for managing OIDC sessions
	SessionManager sessions.SessionManager
}

func NewSessionAuthenticator(
	store sessions.Store,
	cookie string,
	tokenHeader, tokenScheme string,
	strictSessionValidation bool,
	tlsCfg common.TlsConfig,
	sessionManager sessions.SessionManager) Authenticator {

	return &SessionAuthenticator{
		Store:                   store,
		Cookie:                  cookie,
		TokenHeader:             tokenHeader,
		TokenScheme:             tokenScheme,
		StrictSessionValidation: strictSessionValidation,
		TLSConfig:               tlsCfg,
		SessionManager:          sessionManager,
	}
}

func (sa *SessionAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*common.User, bool, error) {
	logger := common.RequestLogger(r, "session authenticator")
	logger.Info("Attempting HTTP session authentication")

	// Get session from header or cookie
	session, authMethod, err := sessions.SessionFromRequest(r, sa.Store, sa.Cookie, sa.TokenHeader)

	// Check if user session is valid
	if err != nil {
		return nil, false, errors.Wrap(err, "couldn't get user session")
	}
	if session.IsNew {
		logger.Info("Failed to retrieve a valid session")
		return nil, false, nil
	}

	ctx := sa.TLSConfig.Context(r.Context())
	token := session.Values[sessions.UserSessionOAuth2Tokens].(oauth2.Token)

	newToken, err := sa.SessionManager.SaveToken(session, ctx, &token, httptest.NewRecorder())
	if err != nil {
		logger.Errorf("Failed to refresh token: %v", err)
		// Access token has expired
		logger.Info("OAuth2 tokens have expired, revoking OIDC session")
		revokeErr := sa.SessionManager.RevokeOIDCSession(ctx, httptest.NewRecorder(),
			session, sa.TLSConfig)
		if revokeErr != nil {
			logger.Errorf("Failed to revoke tokens: %v", revokeErr)
		}
		return nil, false, err
	}

	// User is logged in
	if sa.StrictSessionValidation {
		ctx := r.Context()
		_, err := sa.SessionManager.GetUserInfo(ctx, newToken)
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
			err = sa.SessionManager.RevokeSession(ctx, httptest.NewRecorder(), session, sa.TLSConfig)
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

	// set auth header with user token
	idHeader := session.Values[sessions.UserSessionIDToken].(string)
	// prepend authorization scheme if one is specified
	if sa.TokenScheme != "" {
		idHeader = sa.TokenScheme + " " + idHeader
	}
	w.Header().Set(sa.TokenHeader, idHeader)

	resp := &common.User{
		Name:   session.Values[sessions.UserSessionUserID].(string),
		Groups: groups,
		Extra:  extra,
	}
	return resp, true, nil
}
