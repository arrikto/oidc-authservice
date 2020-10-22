// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"encoding/gob"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

const (
	oidcStateCookie = "oidc_state_csrf"
)

func init() {
	gob.Register(State{})

}

type State struct {
	// FirstVisitedURL is the URL that the user visited when we redirected them
	// to login.
	FirstVisitedURL string
}

func newState(firstVisitedURL string) *State {
	return &State{
		FirstVisitedURL: firstVisitedURL,
	}
}

// createState creates the state parameter from the incoming request, stores
// it in the session store and sets a cookie with the session key.
// It returns the session key, which can be used as the state value to start
// an OIDC authentication request.
func createState(r *http.Request, w http.ResponseWriter,
	store sessions.Store) (string, error) {

	s := newState(r.URL.Path)
	session := sessions.NewSession(store, oidcStateCookie)
	session.ID = createNonce(16)
	session.Options.MaxAge = int(20 * time.Minute)
	session.Values["state"] = *s

	err := session.Save(&http.Request{}, w)
	if err != nil {
		return "", errors.Wrap(err, "error trying to save session")
	}

	// Cookie is persisted in ResponseWriter, make a request to parse it.
	tempReq := &http.Request{Header: make(http.Header)}
	tempReq.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	c, err := tempReq.Cookie(oidcStateCookie)
	if err != nil {
		return "", errors.Wrap(err, "error trying to save session")
	}
	return c.Value, nil
}

// verifyState gets the state from the cookie 'initState' saved. It also gets
// the state from an http param and:
// 1. Confirms the two values match.
// 2. Confirms we issued the state value by decoding it.
//
// Finally, it returns the decoded state value.
func verifyState(r *http.Request, w http.ResponseWriter,
	store sessions.Store) (*State, error) {

	// Get the state from the HTTP param.
	var stateParam = r.FormValue("state")
	if len(stateParam) == 0 {
		return nil, errors.New("Missing url parameter: state")
	}

	// Get the state from the cookie the user-agent sent.
	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil {
		return nil, errors.Errorf("Missing cookie: '%s'", oidcStateCookie)
	}

	// Confirm the two values match.
	if stateParam != stateCookie.Value {
		return nil, errors.New("State value from http params doesn't match value in cookie. Possible CSRF attack.")
	}

	// Retrieve session from store. If it doesn't exist, it may have expired.
	session, err := store.Get(r, oidcStateCookie)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if session.IsNew {
		return nil, errors.New("session not found, maybe it expired")
	}

	state := session.Values["state"].(State)

	// Revoke the session so that each state value can only be used once.
	if err = revokeSession(r.Context(), w, session); err != nil {
		return nil, errors.Wrap(err, "error revoking state session")
	}
	return &state, nil
}
