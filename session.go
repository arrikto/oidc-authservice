package main

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc"
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
// order.
func sessionFromRequest(r *http.Request, store sessions.Store, cookie,
	header string) (*sessions.Session, error) {

	// Get session from header or cookie
	sessionID := getBearerToken(r.Header.Get(header))
	if sessionID != "" {
		return sessionFromID(sessionID, store)
	}
	return store.Get(r, cookie)
}

// revokeSession revokes the given session.
func revokeSession(ctx context.Context, w http.ResponseWriter,
	session *sessions.Session) error {

	// Delete the session by setting its MaxAge to a negative number.
	// This will delete the session from the store and also add a "Set-Cookie"
	// header that will instruct the browser to delete it.
	// XXX: The session.Save function doesn't really need the request, but only
	// uses it for its context.
	session.Options.MaxAge = -1
	r := &http.Request{}
	if err := session.Save(r.WithContext(ctx), w); err != nil {
		return errors.Wrap(err, "Couldn't delete user session")
	}
	return nil
}

// revokeOIDCSession revokes the given session, which is assumed to be an OIDC
// session, for which it also performs the necessary cleanup.
// TODO: In the future, we may want to make this function take a function as
// input, instead of polluting it with extra arguments.
func revokeOIDCSession(ctx context.Context, w http.ResponseWriter,
	session *sessions.Session, provider *oidc.Provider,
	oauth2Config *oauth2.Config, caBundle []byte) error {

	logger := logrus.StandardLogger()

	// Revoke the session's OAuth tokens
	_revocationEndpoint, err := revocationEndpoint(provider)
	if err != nil {
		logger.Warnf("Error getting provider's revocation_endpoint: %v", err)
	} else {
		token := session.Values[userSessionOAuth2Tokens].(oauth2.Token)
		err := revokeTokens(setTLSContext(ctx, caBundle), _revocationEndpoint,
			&token, oauth2Config.ClientID, oauth2Config.ClientSecret)
		if err != nil {
			return errors.Wrap(err, "Error revoking tokens")
		}
		logger.WithField("userid", session.Values[userSessionUserID].(string)).Info("Access/Refresh tokens revoked")
	}

	return revokeSession(ctx, w, session)
}
