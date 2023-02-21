package sessions

import (
	"context"
	"net/http"
	"sync"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/yosssi/boltstore/shared"
	"golang.org/x/oauth2"
)

const (
	// Issue: https://github.com/gorilla/sessions/issues/200
	secureCookieKeyPair = "notNeededBecauseCookieValueIsRandom"

	UserSessionCookie       = "authservice_session"
	UserSessionUserID       = "userid"
	UserSessionGroups       = "groups"
	UserSessionClaims       = "claims"
	UserSessionIDToken      = "idtoken"
	UserSessionOAuth2Tokens = "oauth2tokens"
)

type Store sessions.Store

type ClosableStore interface {
	sessions.Store
	Close() error
}

func NewSession(store Store, name string) *sessions.Session{
	return sessions.NewSession(store, name)
}

// SessionFromID returns a session which has its key in a header.
// XXX: Because the session library we use doesn't support getting a session
// by key, we need to fake a cookie
func SessionFromID(id string, store sessions.Store) (*sessions.Session, error) {
	r := &http.Request{Header: make(http.Header)}
	r.AddCookie(&http.Cookie{
		// XXX: This is needed because the sessions lib we use also encodes
		// cookies with securecookie, which requires passing the correct cookie
		// name during decryption.
		Name:   UserSessionCookie,
		Value:  id,
		Path:   "/",
		MaxAge: 1,
	})
	return store.Get(r, UserSessionCookie)
}

// SessionFromRequest looks for a session id in a header and a cookie, in that
// order. If it doesn't find a valid session in the header, it will then check
// the cookie.
func SessionFromRequest(r *http.Request, store sessions.Store, cookie,
	header string) (*sessions.Session, string, error) {

	var authMethod string
	logger := common.RequestLogger(r, "session authenticator")
	// Try to get session from header
	sessionID := common.GetBearerToken(r.Header.Get(header))
	if sessionID != "" {
		s, err := SessionFromID(sessionID, store)
		if err == nil && !s.IsNew {
			logger.Debugf("Loading session from header %s", header)
			// Authentication using header successfully completed
			authMethod = "header"
			return s, authMethod, nil
		}
		logger.Debugf("Header %s didn't contain a valid session id: %v", header, err)
	}
	// Header failed, try to get session from cookie
	logger.Debugf("Loading session from cookie %s", cookie)
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

// RevokeOIDCSession revokes the given session, which is assumed to be an OIDC
// session, for which it also performs the necessary cleanup.
// TODO: In the future, we may want to make this function take a function as
// input, instead of polluting it with extra arguments.
func RevokeOIDCSession(ctx context.Context, w http.ResponseWriter,
	session *sessions.Session, provider oidc.Provider,
	oauth2Config *oauth2.Config, caBundle []byte) error {

	logger := common.StandardLogger()

	// Revoke the session's OAuth tokens
	_revocationEndpoint, err := oidc.RevocationEndpoint(provider)
	if err != nil {
		logger.Warnf("Error getting provider's revocation_endpoint: %v", err)
	} else {
		token := session.Values[UserSessionOAuth2Tokens].(oauth2.Token)
		err := oidc.RevokeTokens(common.SetTLSContext(ctx, caBundle),
		    _revocationEndpoint, &token, oauth2Config.ClientID, oauth2Config.ClientSecret)
		if err != nil {
			return errors.Wrap(err, "Error revoking tokens")
		}
		logger.WithField("userid", session.Values[UserSessionUserID].(string)).Info("Access/Refresh tokens revoked")
	}

	return revokeSession(ctx, w, session)
}

var mutex sync.Mutex

// SaveToken triggers oidc.TokenSource to refresh access and refresh token
// if they have expired and saves them to the session
func SaveToken(session *sessions.Session, ctx context.Context,
	config *oauth2.Config, token *oauth2.Token,
	w http.ResponseWriter) (*oauth2.Token, error) {

	logger := common.StandardLogger()

	newToken, new, err := oidc.TokenSource(ctx, config, token)

	if new {
		mutex.Lock()
		defer mutex.Unlock()
		session.Values[UserSessionOAuth2Tokens] = newToken
		r := &http.Request{}
		if err := session.Save(r.WithContext(ctx), w); err != nil {
			logger.Fatalf("Failed to update token in session: %v", err)
		}
		logger.Infof("Updated token in session")
	}
	return newToken, err
}

// InitiateSessionStores initiates both the required stores for the:
// * users sessions
// * OIDC states
// Based on the configured session store (boltdb, or redis) this function will
// return these two session stores, or will terminate the execution with a fatal
// log message.
func InitiateSessionStores(c *common.Config) (ClosableStore, ClosableStore) {
	logger := common.StandardLogger()

	var store, oidcStateStore ClosableStore
	var err error
	switch c.SessionStoreType {
	case "boltdb":
		// Setup session store
		store, err = newBoltDBSessionStore(c.SessionStorePath, shared.DefaultBucketName, false)
		if err != nil {
			logger.Fatalf("Error creating session store: %v", err)
		}
		// Setup state store
		oidcStateStore, err = newBoltDBSessionStore(c.OIDCStateStorePath, "oidc_state", true)
		if err != nil {
			logger.Fatalf("Error creating oidc state store: %v", err)
		}
	case "redis":
		// Setup session store
		store, err = newRedisSessionStore(c.SessionStoreRedisAddr, c.SessionStoreRedisPWD, "", c.SessionStoreRedisDB)
		if err != nil {
			logger.Fatalf("Error creating session store: %v", err)
		}
		// Setup state store
		oidcStateStore, err = newRedisSessionStore(c.SessionStoreRedisAddr, c.SessionStoreRedisPWD, "oidc_state:", c.SessionStoreRedisDB)
		if err != nil {
			logger.Fatalf("Error creating session store: %v", err)
		}
	default:
		logger.Fatalf("Unsupported session store type: %s", c.SessionStoreType)
	}

	return store, oidcStateStore
}
