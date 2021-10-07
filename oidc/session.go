package oidc

import (
	"context"
	"net/http"
	"net/url"
	"time"

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

type SessionManager struct {
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
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
		provider:     provider,
		oauth2Config: oauth2Config,
	}
}

func (s *SessionManager) AuthCodeURL(state string) string {
	return s.oauth2Config.AuthCodeURL(state)
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

func (s *SessionManager) Verify(ctx context.Context, idToken string) (*oidc.IDToken, error) {
	verifier := s.provider.Verifier(&oidc.Config{ClientID: s.oauth2Config.ClientID})
	return verifier.Verify(ctx, idToken)
}
