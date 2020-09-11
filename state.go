// Copyright © 2019 Arrikto Inc.  All Rights Reserved.
//
// Utils related to handling the OIDC state parameter for CSRF.
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest

package main

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/pkg/errors"
)

const (
	oauthStateCookie = "oidc_state_csrf"
)

var secureCookie = securecookie.New(
	// Hash Key
	securecookie.GenerateRandomKey(64),
	// Encryption Key
	securecookie.GenerateRandomKey(32),
)

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

// initState creates the state parameter from the incoming request, hashes it
// with HMAC, encrypts it and stores it in a cookie. Finally, it returns the
// state value so that the caller can use it in the response's URL parameters.
func initState(r *http.Request, w http.ResponseWriter) (string, error) {
	state := newState(r.URL.String())
	encoded, err := secureCookie.Encode(oauthStateCookie, state)
	if err != nil {
		return "", errors.Wrap(err, "Failed to save state in encrypted cookie.")
	}
	cookie := &http.Cookie{
		Name:     oauthStateCookie,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(20 * time.Minute),
	}
	http.SetCookie(w, cookie)
	return encoded, nil
}

// verifyState gets the state from the cookie 'initState' saved. It also gets
// the state from an http param and:
// 1. Confirms the two values match.
// 2. Confirms we issued the state value by decoding it.
//
// Finally, it returns the decoded state value.
func verifyState(r *http.Request) (*State, error) {
	var stateParam = r.FormValue("state")
	if len(stateParam) == 0 {
		return nil, errors.New("Missing url parameter: state")
	}

	// If state is loaded, then it's correct, as it is saved by its id.
	stateCookie, err := r.Cookie(oauthStateCookie)
	if err != nil {
		return nil, errors.Errorf("Missing cookie: '%s'", oauthStateCookie)
	}
	if stateParam != stateCookie.Value {
		return nil, errors.New("State value from http params doesn't match value in cookie. Possible CSRF attack.")
	}

	var state *State
	err = secureCookie.Decode(oauthStateCookie, stateParam, &state)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to decode oauth state parameter.")
	}
	return state, nil
}
