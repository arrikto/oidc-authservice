package main

import (
	"net/http"

	"github.com/arrikto/oidc-authservice/logger"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/arrikto/oidc-authservice/svc"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type idTokenAuthenticator struct {
	header      string // header name where id token is stored
	provider    oidc.IdProvider
	clientID    string // need client id to verify the id token
	userIDClaim string // retrieve the userid if the claim exists
	groupsClaim string
	tlsCfg      svc.TlsConfig
}

func (s *idTokenAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := logger.ForRequest(r)

	// get id-token from header
	bearer := getBearerToken(r.Header.Get(s.header))
	if len(bearer) == 0 {
		return nil, false, nil
	}

	ctx := s.tlsCfg.Context(r.Context())

	// Verifying received ID token
	verifier := s.provider.Verifier(oidc.NewOidcConfig(s.clientID))
	token, err := verifier.Verify(ctx, bearer)
	if err != nil {
		logger.Errorf("id-token verification failed: %v", err)
		return nil, false, nil
	}

	claims, err := oidc.NewClaims(token, s.userIDClaim, s.groupsClaim)
	if err != nil {
		logger.Errorf("retrieving user claims failed: %v", err)
		return nil, false, nil
	}

	userID, err := claims.UserID()
	if err != nil {
		// No USERID_CLAIM, pass this authenticator
		logger.Error("USERID_CLAIM doesn't exist in the id token")
		return nil, false, nil
	}

	groups := claims.Groups()

	resp := &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   userID,
			Groups: groups,
		},
	}
	return resp, true, nil
}
