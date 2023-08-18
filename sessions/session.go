package sessions

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/arrikto/oidc-authservice/common"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/yosssi/boltstore/shared"
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

const (
	SessionErrorUnauth   = 0
	SessionErrorNotFound = 1
)

type Store sessions.Store

type ClosableStore interface {
	sessions.Store
	Close() error
}

func NewSession(store Store, name string) *sessions.Session {
	return sessions.NewSession(store, name)
}

type SessionError struct {
	Message string
	Code    int32
}

func (e *SessionError) Error() string {
	return e.Message
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

// SessionForLogout looks for the session id to log out
func SessionForLogout(r *http.Request, store sessions.Store, header string) (*sessions.Session, error) {
	sessionID := common.GetBearerToken(r.Header.Get(header))
	if sessionID == "" {
		message := fmt.Sprintf(
			"Request doesn't have a session value in header '%s'", header)
		return nil, &SessionError{Message: message, Code: SessionErrorUnauth}
	}

	session, err := SessionFromID(sessionID, store)
	if err != nil {
		message := fmt.Sprintf("Couldn't get user session: %v", err)
		return nil, &SessionError{Message: message, Code: SessionErrorNotFound}
	}

	if session.IsNew {
		message := "Request doesn't have a valid session."
		return nil, &SessionError{Message: message, Code: SessionErrorUnauth}
	}

	return session, nil
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

var mutex sync.Mutex

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
	case "redisfailover":
		// Setup session store
		store, err = newRedisFailoverSessionStore(c.SessionStoreRedisAddr, c.SessionStoreRedisPWD, "", c.SessionStoreRedisDB)
		if err != nil {
			logger.Fatalf("Error creating session store: %v", err)
		}
		// Setup state store
		oidcStateStore, err = newRedisFailoverSessionStore(c.SessionStoreRedisAddr, c.SessionStoreRedisPWD, "oidc_state:", c.SessionStoreRedisDB)
		if err != nil {
			logger.Fatalf("Error creating session store: %v", err)
		}
	default:
		logger.Fatalf("Unsupported session store type: %s", c.SessionStoreType)
	}

	return store, oidcStateStore
}
