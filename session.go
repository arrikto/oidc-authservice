package main

import (
	"context"
	"net/http"

	"github.com/arrikto/oidc-authservice/logger"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/arrikto/oidc-authservice/svc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	userSessionCookie       = "authservice_session"
	userSessionUserID       = "userid"
	userSessionGroups       = "groups"
	userSessionClaims       = "claims"
	userSessionIDToken      = "idtoken"
	userSessionOAuth2Tokens = "oauth2tokens"
)

// sessionFromRequestHeader returns a session which has its key in a header.
// XXX: Because the session library we use doesn't support getting a session
// by key, we need to fake a cookie
func sessionFromID(id string, store sessions.Store) (*sessions.Session, error) {
	r := &http.Request{Header: make(http.Header)}
	r.AddCookie(&http.Cookie{
		// XXX: This is needed because the sessions lib we use also encodes
		// cookies with securecookie, which requires passing the correct cookie
		// name during decryption.
		Name:   userSessionCookie,
		Value:  id,
		Path:   "/",
		MaxAge: 1,
	})
	return store.Get(r, userSessionCookie)
}

// sessionFromRequest looks for a session id in a header and a cookie, in that
// order. If it doesn't find a valid session in the header, it will then check
// the cookie.
func sessionFromRequest(r *http.Request, store sessions.Store, cookie,
	header string) (*sessions.Session, error) {

	logger := logger.ForRequest(r)
	// Try to get session from header
	sessionID := getBearerToken(r.Header.Get(header))
	if sessionID != "" {
		s, err := sessionFromID(sessionID, store)
		if err == nil && !s.IsNew {
			logger.Infof("Loading session from header %s", header)
			return s, nil
		}
		logger.Debugf("Header %s didn't contain a valid session id: %v", header, err)
	}
	// Header failed, try to get session from cookie
	logger.Infof("Loading session from cookie %s", cookie)
	return store.Get(r, cookie)
}

// revokeOIDCSession revokes the given session, which is assumed to be an OIDC
// session, for which it also performs the necessary cleanup.
// TODO: In the future, we may want to make this function take a function as
// input, instead of polluting it with extra arguments.
func revokeOIDCSession(ctx context.Context, w http.ResponseWriter,
	session *sessions.Session, provider oidc.IdProvider,
	oauth2Config *oauth2.Config, tlsCfg svc.TlsConfig) error {

	logger := logrus.StandardLogger()

	// Revoke the session's OAuth tokens
	_revocationEndpoint, err := revocationEndpoint(provider)
	if err != nil {
		logger.Warnf("Error getting provider's revocation_endpoint: %v", err)
	} else {
		token := session.Values[userSessionOAuth2Tokens].(oauth2.Token)
		err := revokeTokens(tlsCfg.Context(ctx), _revocationEndpoint,
			&token, oauth2Config.ClientID, oauth2Config.ClientSecret)
		if err != nil {
			return errors.Wrap(err, "Error revoking tokens")
		}
		logger.WithField("userid", session.Values[userSessionUserID].(string)).Info("Access/Refresh tokens revoked")
	}

	return oidc.RevokeSession(ctx, w, session)
}
