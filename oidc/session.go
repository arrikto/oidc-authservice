package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/arrikto/oidc-authservice/logger"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	UserSessionCookie       = "authservice_session"
	UserSessionUserID       = "userid"
	UserSessionGroups       = "groups"
	UserSessionClaims       = "claims"
	UserSessionIDToken      = "idtoken"
	UserSessionOAuth2Tokens = "oauth2tokens"

	SessionErrorUnauth   = 0
	SessionErrorNotFound = 1
)

// revokeSession revokes the given session.
func RevokeSession(ctx context.Context, w http.ResponseWriter,
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

type SessionError struct {
	Message string
	Code    int32
}

func (e *SessionError) Error() string {
	return e.Message
}

type SessionStore struct {
	store                    sessions.Store
	authHeader               string
	sessionCookie            string
	sessionDomain            string
	userIDClaim, groupsClaim string
	sessionMaxAgeSeconds     int
	sessionSameSite          http.SameSite
}

func NewSessionStore(
	store sessions.Store,
	authHeader string,
	sessionCookie string,
	sessionDomain string,
	userIDClaim, groupsClaim string,
	sessionMaxAgeSeconds int,
	sessionSameSiteCfg string) SessionStore {

	// Use Lax mode as the default
	sessionSameSite := http.SameSiteLaxMode
	switch sessionSameSiteCfg {
	case "None":
		sessionSameSite = http.SameSiteNoneMode
	case "Strict":
		sessionSameSite = http.SameSiteStrictMode
	}
	return SessionStore{
		store:                store,
		authHeader:           authHeader,
		sessionCookie:        sessionCookie,
		sessionDomain:        sessionDomain,
		userIDClaim:          userIDClaim,
		groupsClaim:          groupsClaim,
		sessionMaxAgeSeconds: sessionMaxAgeSeconds,
		sessionSameSite:      sessionSameSite,
	}
}

// SessionFromRequestHeader returns a session which has its key in a header.
// XXX: Because the session library we use doesn't support getting a session
// by key, we need to fake a cookie
func (s *SessionStore) sessionFromID(id string) (*sessions.Session, error) {
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

	return s.store.Get(r, UserSessionCookie)
}

func (s *SessionStore) NewSession(
	r *http.Request,
	w http.ResponseWriter,
	userInfo *UserInfo,
	rawIDToken string,
	oauth2Tokens *oauth2.Token) (*sessions.Session, error) {
	claims, err := NewClaims(
		userInfo,
		s.userIDClaim,
		s.groupsClaim,
	)

	if err != nil {
		return nil, errors.New("Not able to fetch userinfo claims")
	}

	// User is authenticated, create new session.
	session := sessions.NewSession(s.store, UserSessionCookie)
	session.Options.MaxAge = s.sessionMaxAgeSeconds
	session.Options.Path = "/"
	// Extra layer of CSRF protection
	session.Options.SameSite = s.sessionSameSite
	session.Options.Domain = s.sessionDomain
	session.Options.HttpOnly = true
	session.Options.Secure = true

	userID, err := claims.UserID()
	if err != nil {
		return nil, err
	}

	session.Values[UserSessionUserID] = userID
	session.Values[UserSessionGroups] = claims.Groups()
	session.Values[UserSessionClaims] = claims.Claims()
	session.Values[UserSessionIDToken] = rawIDToken
	session.Values[UserSessionOAuth2Tokens] = oauth2Tokens

	return session, session.Save(r, w)
}

// SessionForLogout looks for the session id to log out
func (s *SessionStore) SessionForLogout(r *http.Request) (*sessions.Session, error) {
	sessionID := GetBearerToken(r.Header.Get(s.authHeader))
	if sessionID == "" {
		message := fmt.Sprintf(
			"Request doesn't have a session value in header '%s'", s.authHeader)
		return nil, &SessionError{Message: message, Code: SessionErrorUnauth}
	}

	session, err := s.sessionFromID(sessionID)
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
func (s *SessionStore) SessionFromRequest(r *http.Request) (*sessions.Session, error) {
	logger := logger.ForRequest(r)

	// Try to get session from header
	sessionID := GetBearerToken(r.Header.Get(s.authHeader))

	if sessionID != "" {
		session, err := s.sessionFromID(sessionID)
		if err == nil && !session.IsNew {
			logger.Infof("Loading session from header %s", s.authHeader)
			return session, nil
		}

		logger.Debugf(
			"Header %s didn't contain a valid session id: %v", s.authHeader, err)
	}

	// Header failed, try to get session from cookie
	logger.Infof("Loading session from cookie %s", s.sessionCookie)
	return s.store.Get(r, s.sessionCookie)
}

type SessionManager struct {
	provider      *oidc.Provider
	oauth2Config  *oauth2.Config
	deviceAuthUrl string
}

func makeProvider(ctx context.Context, providerURL *url.URL) *oidc.Provider {
	for {
		provider, err := oidc.NewProvider(ctx, providerURL.String())
		if err == nil {
			return provider
		}
		logrus.Errorf("OIDC provider setup failed, retrying in 10 seconds: %v", err)
		time.Sleep(10 * time.Second)
	}

	return nil
}

func NewSessionManager(ctx context.Context,
	clientID, clientSecret string,
	providerURL, oidcAuthURL, redirectURL *url.URL,
	scopes []string) SessionManager {

	provider := makeProvider(ctx, providerURL)

	endpoint := provider.Endpoint()
	if len(oidcAuthURL.String()) > 0 {
		endpoint.AuthURL = oidcAuthURL.String()
	}

	// Get OIDC Session Authenticator
	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     endpoint,
		RedirectURL:  redirectURL.String(),
		Scopes:       scopes,
	}

	return SessionManager{
		provider:      provider,
		oauth2Config:  oauth2Config,
		deviceAuthUrl: providerURL.String() + "/device/code",
	}
}

func (s *SessionManager) AuthCodeURL(state string) string {
	return s.oauth2Config.AuthCodeURL(state)
}

func (s *SessionManager) DeviceAuthURL() string {
	return s.deviceAuthUrl
}

func (s *SessionManager) GetUserInfo(
	ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	// TokenSource takes care of automatically renewing the access token.
	return GetUserInfo(ctx, s.provider, s.oauth2Config.TokenSource(ctx, token))
}

func (s *SessionManager) ExchangeCode(
	ctx context.Context, authCode string) (*oauth2.Token, error) {
	return s.oauth2Config.Exchange(ctx, authCode)
}

func (s *SessionManager) RevokeSession(
	ctx context.Context, w http.ResponseWriter, session *sessions.Session) error {
	// RevokeSession revokes the given session, which is assumed to be an OIDC
	// session, for which it also performs the necessary cleanup.
	// TODO: In the future, we may want to make this function take a function as
	// input, instead of polluting it with extra arguments.
	logger := logrus.StandardLogger()

	// Revoke the session's OAuth tokens
	revocationEndpoint, err := revocationEndpoint(s.provider)
	if err != nil {
		logger.Warnf("Error getting provider's revocation_endpoint: %v", err)
	} else {
		token := session.Values[UserSessionOAuth2Tokens].(oauth2.Token)
		err := revokeTokens(ctx, revocationEndpoint,
			&token, s.oauth2Config.ClientID, s.oauth2Config.ClientSecret)
		if err != nil {
			return errors.Wrap(err, "Error revoking tokens")
		}
		userID := session.Values[UserSessionUserID].(string)
		logger.WithField("userid", userID).Info("Access/Refresh tokens revoked")
	}

	return RevokeSession(ctx, w, session)
}

func (s *SessionManager) Verify(
	ctx context.Context, idToken, clientID string) (*oidc.IDToken, error) {
	if clientID == "" {
		clientID = s.oauth2Config.ClientID
	}
	verifier := s.provider.Verifier(&oidc.Config{ClientID: clientID})
	return verifier.Verify(ctx, idToken)
}
