package main

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/yosssi/boltstore/shared"
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
	header string) (*sessions.Session, string, error) {

	var authMethod string
	logger := loggerForRequest(r, "session authenticator")
	// Try to get session from header
	sessionID := getBearerToken(r.Header.Get(header))
	if sessionID != "" {
		s, err := sessionFromID(sessionID, store)
		if err == nil && !s.IsNew {
			logger.Infof("Loading session from header %s", header)
			// Authentication using header successfully completed
			authMethod = "header"
			return s, authMethod, nil
		}
		logger.Infof("Header %s didn't contain a valid session id: %v", header, err)
	}
	// Header failed, try to get session from cookie
	logger.Infof("Loading session from cookie %s", cookie)
	s, err := store.Get(r, cookie)
	if err == nil && !s.IsNew {
		authMethod = "cookie"
	}
	return s, authMethod, err
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

type ClosableStore interface {
	sessions.Store
	Close() error
}

// initiateSessionStores initiates both the required stores for the:
// * users sessions
// * OIDC states
// Based on the configured session store (boltdb, or redis) this function will
// return these two session stores, or will terminate the execution with a fatal
// log message.
func initiateSessionStores(c *config) (ClosableStore, ClosableStore) {

	logger := logrus.StandardLogger()

	logger.Infof("Configured session store type: %s", c.SessionStoreType)
	var store, oidcStateStore ClosableStore
	var err error
	switch c.SessionStoreType {
	case "boltdb":
		// Setup session store
		store, err = newBoltDBSessionStore(c.SessionStorePath, shared.DefaultBucketName, false)
		if err != nil {
			logger.Fatalf("Error creating session store: %v", err)
		}
		defer store.Close()
		// Setup state store
		oidcStateStore, err = newBoltDBSessionStore(c.OIDCStateStorePath, "oidc_state", true)
		if err != nil {
			logger.Fatalf("Error creating oidc state store: %v", err)
		}
		defer oidcStateStore.Close()
	case "redis":
		// Setup session store
		store, err = newRedisSessionStore(c.SessionStoreRedisAddr, c.SessionStoreRedisPWD, "", c.SessionStoreRedisDB)
		if err != nil {
			logger.Fatalf("Error creating session store: %v", err)
		}
		defer store.Close()
		// Setup state store
		oidcStateStore, err = newRedisSessionStore(c.SessionStoreRedisAddr, c.SessionStoreRedisPWD, "oidc_state:", c.SessionStoreRedisDB)
		if err != nil {
			logger.Fatalf("Error creating session store: %v", err)
		}
		defer oidcStateStore.Close()
	default:
		logger.Fatalf("Unsupported session store type: %s", c.SessionStoreType)
	}

	return store, oidcStateStore
}
