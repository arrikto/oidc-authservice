package sessions

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"

	goidc "github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type SessionManager struct {
	provider      *goidc.Provider
	oauth2Config  *oauth2.Config
	deviceAuthURL string
}

func makeProvider(ctx context.Context, providerURL *url.URL) *goidc.Provider {
	for {
		provider, err := goidc.NewProvider(ctx, providerURL.String())
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
		deviceAuthURL: providerURL.String() + "/device/code",
	}
}

func (s *SessionManager) AuthCodeURL(state string) string {
	return s.oauth2Config.AuthCodeURL(state)
}

func (s *SessionManager) DeviceAuthURL() string {
	return s.deviceAuthURL
}

func (s *SessionManager) GetUserInfo(
	ctx context.Context, token *oauth2.Token) (*oidc.UserInfo, error) {
	return oidc.GetUserInfo(ctx, s.provider, token)
}

func (s *SessionManager) ExchangeCode(
	ctx context.Context, authCode string) (*oauth2.Token, error) {
	return s.oauth2Config.Exchange(ctx, authCode)
}

func (s *SessionManager) RevokeSession(
	ctx context.Context, w http.ResponseWriter, session *sessions.Session, tlsCfg common.TlsConfig) error {
	return s.RevokeOIDCSession(ctx, w, session, tlsCfg)
}

func (s *SessionManager) Verify(ctx context.Context, idToken, clientID string) (*goidc.IDToken, error) {
	if clientID == "" {
		clientID = s.oauth2Config.ClientID
	}
	verifier := s.provider.Verifier(&goidc.Config{ClientID: clientID})
	return verifier.Verify(ctx, idToken)
}

func (s *SessionManager) VerifyWithClientId(ctx context.Context,
	clientId string, idToken string) (*goidc.IDToken, error) {
	verifier := s.provider.Verifier(&goidc.Config{ClientID: clientId})
	return verifier.Verify(ctx, idToken)
}

// TokenSource is a wrapper around oauth2.Config.TokenSource that additionally
// returns a boolean indicator for a token refresh.
func (s *SessionManager) TokenSource(ctx context.Context,
	token *oauth2.Token) (*oauth2.Token, bool, error) {

	tokenSource := s.oauth2Config.TokenSource(ctx, token)

	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, false, errors.Errorf("oidc: get access token: %v", err)
	}

	// Check if access token has been refreshed
	if (newToken.AccessToken != token.AccessToken) || (newToken.RefreshToken != token.RefreshToken) {
		return newToken, true, nil
	}

	return token, false, nil
}

// SaveToken triggers oidc.TokenSource to refresh access and refresh token
// if they have expired and saves them to the session
func (s *SessionManager) SaveToken(session *sessions.Session, ctx context.Context,
	token *oauth2.Token,
	w http.ResponseWriter) (*oauth2.Token, error) {

	logger := common.StandardLogger()

	newToken, new, err := s.TokenSource(ctx, token)

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

// RevokeOIDCSession revokes the given session, which is assumed to be an OIDC
// session, for which it also performs the necessary cleanup.
// TODO: In the future, we may want to make this function take a function as
// input, instead of polluting it with extra arguments.
func (s *SessionManager) RevokeOIDCSession(ctx context.Context, w http.ResponseWriter,
	session *sessions.Session, tlsCfg common.TlsConfig) error {

	logger := common.StandardLogger()

	// Revoke the session's OAuth tokens
	_revocationEndpoint, err := oidc.RevocationEndpoint(s.provider)
	if err != nil {
		logger.Warnf("Error getting provider's revocation_endpoint: %v", err)
	} else {
		token := session.Values[UserSessionOAuth2Tokens].(oauth2.Token)
		err := oidc.RevokeTokens(tlsCfg.Context(ctx),
			_revocationEndpoint, &token, s.oauth2Config.ClientID, s.oauth2Config.ClientSecret)
		if err != nil {
			return errors.Wrap(err, "Error revoking tokens")
		}
		logger.WithField("userid", session.Values[UserSessionUserID].(string)).Info("Access/Refresh tokens revoked")
	}

	return revokeSession(ctx, w, session)
}
