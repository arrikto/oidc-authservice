// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"net/http"
	"net/http/httptest"
	"time"
)

const oidcLoginSessionCookie = "non_existent_cookie"

type state struct {
	origURL string
}

func newState(origURL string) *state {
	return &state{
		origURL: origURL,
	}
}

// load retrieves a state from the store given its id.
func load(store sessions.Store, id string) (*state, error) {
	// Make a fake request so that the store will find the cookie
	r := &http.Request{Header: make(http.Header)}
	r.AddCookie(&http.Cookie{Name: oidcLoginSessionCookie, Value: id, MaxAge: 10})

	session, err := store.Get(r, oidcLoginSessionCookie)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if session.IsNew {
		return nil, errors.New("session does not exist")
	}

	return &state{
		origURL: session.Values["origURL"].(string),
	}, nil
}

// save persists a state to the store and returns the entry's id.
func (s *state) save(store sessions.Store) (string, error) {
	session := sessions.NewSession(store, oidcLoginSessionCookie)
	session.ID = createNonce(16)
	session.Options.MaxAge = int(time.Hour)
	session.Values["origURL"] = s.origURL

	// The current gorilla/sessions Store interface doesn't allow us
	// to set the session ID.
	// Because of that, we have to retrieve it from the cookie value.
	w := httptest.NewRecorder()
	err := session.Save(&http.Request{}, w)
	if err != nil {
		return "", errors.Wrap(err, "error trying to save session")
	}
	// Cookie is persisted in ResponseWriter, make a request to parse it.
	r := &http.Request{Header: make(http.Header)}
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	c, err := r.Cookie(oidcLoginSessionCookie)
	if err != nil {
		return "", errors.Wrap(err, "error trying to save session")
	}
	return c.Value, nil
}
