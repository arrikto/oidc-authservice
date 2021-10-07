package main

import (
	"fmt"
	"net/http"

	"github.com/arrikto/oidc-authservice/logger"
	"github.com/arrikto/oidc-authservice/oidc"

	"github.com/gorilla/sessions"
)

const (
	SessionErrorUnauth   = 0
	SessionErrorNotFound = 1
)

type SessionError struct {
	Message string
	Code    int32
}

func (e *SessionError) Error() string {
	return e.Message
}

// SessionFromRequestHeader returns a session which has its key in a header.
// XXX: Because the session library we use doesn't support getting a session
// by key, we need to fake a cookie
func sessionFromID(id string, store sessions.Store) (*sessions.Session, error) {
	r := &http.Request{Header: make(http.Header)}
	r.AddCookie(&http.Cookie{
		// XXX: This is needed because the sessions lib we use also encodes
		// cookies with securecookie, which requires passing the correct cookie
		// name during decryption.
		Name:   oidc.UserSessionCookie,
		Value:  id,
		Path:   "/",
		MaxAge: 1,
	})
	return store.Get(r, oidc.UserSessionCookie)
}

// SessionForLogout looks for the session id to log out
func SessionForLogout(r *http.Request, store sessions.Store, header string) (*sessions.Session, error) {
	sessionID := getBearerToken(r.Header.Get(header))
	if sessionID == "" {
		message := fmt.Sprintf(
			"Request doesn't have a session value in header '%s'", header)
		return nil, &SessionError{Message: message, Code: SessionErrorUnauth}
	}

	session, err := sessionFromID(sessionID, store)
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
func sessionFromRequest(r *http.Request, store sessions.Store, cookie, header string) (*sessions.Session, error) {
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
