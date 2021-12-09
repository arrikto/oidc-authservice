package oidc

import (
	"encoding/gob"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	SessionValueState = "state"
	OidcStateCookie   = "oidc_state_csrf"
)

func init() {
	gob.Register(State{})

	// Register type for claims.
	gob.Register(map[string]interface{}{})
	gob.Register(oauth2.Token{})
	gob.Register(oidc.IDToken{})
}

type Config struct {
	SchemeDefault string
	SchemeHeader  string
	SessionDomain string
}

type StateFunc func(*http.Request) *State

func NewStateFunc(config *Config) StateFunc {
	if len(config.SessionDomain) > 0 {
		return newSchemeAndHost(config)
	}
	return relativeURL
}

func firstVisitedURL(u *url.URL) string {
	firstVisited, err := url.Parse("")
	if err != nil {
		panic(err)
	}
	firstVisited.Path = u.Path
	firstVisited.RawPath = u.RawPath
	firstVisited.RawQuery = u.RawQuery

	return firstVisited.String()
}

func relativeURL(r *http.Request) *State {
	return &State{
		FirstVisitedURL: firstVisitedURL(r.URL),
	}
}

func newSchemeAndHost(config *Config) StateFunc {
	return func(r *http.Request) *State {
		// Use header value if it exists
		s := r.Header.Get(config.SchemeHeader)
		if s == "" {
			s = config.SchemeDefault
		}
		// XXX Could return an error here. Would require changing the StateFunc type
		if !strings.HasSuffix(r.Host, config.SessionDomain) {
			log.Warnf("Request host %q is not a subdomain of %q", r.Host, config.SessionDomain)
		}
		return &State{
			FirstVisitedURL: s + "://" + r.Host + firstVisitedURL(r.URL),
		}
	}
}

type OidcStateStore struct {
	store           sessions.Store
	sessionDomain   string
}

type State struct {
	// FirstVisitedURL is the URL that the user visited when we redirected them
	// to login.
	FirstVisitedURL string
}

func NewOidcStateStore(
	store sessions.Store,
	sessionDomain string) OidcStateStore {
	return OidcStateStore{
		store:           store,
		sessionDomain:   sessionDomain,
	}
}

// Session from state cookie
func (s *OidcStateStore) sessionFromStateCookie(r *http.Request) (*sessions.Session, error) {
	// Get the state from the HTTP param.
	var stateParam = r.FormValue("state")
	if len(stateParam) == 0 {
		return nil, errors.New("Missing url parameter: state")
	}

	// Get the state from the cookie the user-agent sent.
	stateCookie, err := r.Cookie(OidcStateCookie)
	if err != nil {
		return nil, errors.Errorf("Missing cookie: '%s'", OidcStateCookie)
	}

	// Confirm the two values match.
	if stateParam != stateCookie.Value {
		return nil, errors.New("State value from http params doesn't match " +
			"value in cookie. Possible reasons for this error include " +
			"opening the login form in more than 1 browser tabs OR a CSRF " +
			"attack.")
	}

	// Retrieve session from store. If it doesn't exist, it may have expired.
	session, err := s.store.Get(r, OidcStateCookie)

	if err != nil {
		return nil, errors.WithStack(err)
	}

	if session.IsNew {
		return nil, errors.New("State value not found in store, maybe it expired")
	}

	return session, nil
}

func (s *OidcStateStore) CreateState(
	r *http.Request, w http.ResponseWriter, fn StateFunc) error {
	state := fn(r)
	session := sessions.NewSession(s.store, OidcStateCookie)
	session.Options.MaxAge = int(20 * time.Minute)
	session.Options.Path = "/"
	session.Options.Domain = s.sessionDomain
	session.Values[SessionValueState] = *state

	return session.Save(r, w)
}

// Verify gets the state from the cookie 'initState' saved. It also gets
// the state from an http param and:
// 1. Confirms the two values match (CSRF check).
// 2. Confirms the value is still valid by retrieving the session it points to.
//    The state value might be invalid if it has been used before or the session
//    expired.
//
// Finally, it returns a State struct, which contains information associated
// with the particular OIDC flow.
func (s *OidcStateStore) Verify(r *http.Request, w http.ResponseWriter) (*State, error) {
	// Retrieve session from store. If it doesn't exist, it may have expired.
	session, err := s.sessionFromStateCookie(r)
	if err != nil {
		return nil, err
	}

	state := session.Values[SessionValueState].(State)
	// Revoke the session so that each state value can only be used once.
	if err = RevokeSession(r.Context(), w, session); err != nil {
		return nil, errors.Wrap(err, "error revoking state session")
	}
	return &state, nil
}
