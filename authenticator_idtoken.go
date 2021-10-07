package main

import (
	"net/http"

	"github.com/arrikto/oidc-authservice/svc"
	oidc "github.com/coreos/go-oidc"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type idTokenAuthenticator struct {
	header      string // header name where id token is stored
	provider    *oidc.Provider
	clientID    string // need client id to verify the id token
	userIDClaim string // retrieve the userid if the claim exists
	groupsClaim string
	tlsCfg      svc.TlsConfig
}

func (s *idTokenAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := loggerForRequest(r)

	// get id-token from header
	bearer := getBearerToken(r.Header.Get(s.header))
	if len(bearer) == 0 {
		return nil, false, nil
	}

	ctx := s.tlsCfg.Context(r.Context())

	// Verifying received ID token
	verifier := s.provider.Verifier(&oidc.Config{ClientID: s.clientID})
	token, err := verifier.Verify(ctx, bearer)
	if err != nil {
		logger.Errorf("id-token verification failed: %v", err)
		return nil, false, nil
	}

	var claims map[string]interface{}
	if err := token.Claims(&claims); err != nil {
		logger.Errorf("retrieving user claims failed: %v", err)
		return nil, false, nil
	}

	if claims[s.userIDClaim] == nil {
		// No USERID_CLAIM, pass this authenticator
		logger.Error("USERID_CLAIM doesn't exist in the id token")
		return nil, false, nil
	}

	groups := []string{}
	groupsClaim := claims[s.groupsClaim]
	if groupsClaim != nil {
		groups = interfaceSliceToStringSlice(groupsClaim.([]interface{}))
	}

	resp := &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   claims[s.userIDClaim].(string),
			Groups: groups,
		},
	}
	return resp, true, nil
}
