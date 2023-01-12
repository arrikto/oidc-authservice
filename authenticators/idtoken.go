package authenticators

import (
	"net/http"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/arrikto/oidc-authservice/oidc"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type IDTokenAuthenticator struct {
	Header      string // header name where id token is stored
	CaBundle    []byte
	Provider    oidc.Provider
	ClientID    string // need client id to verify the id token
	UserIDClaim string // retrieve the userid if the claim exists
	GroupsClaim string
}

func (s *IDTokenAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := common.RequestLogger(r, "idtoken authenticator")

	// get id-token from header
	bearer := common.GetBearerToken(r.Header.Get(s.Header))
	if len(bearer) == 0 {
		logger.Debug("No bearer token found")
		return nil, false, nil
	}

	ctx := common.SetTLSContext(r.Context(), s.CaBundle)

	// Verifying received ID token
	verifier := s.Provider.Verifier(oidc.NewConfig(s.ClientID))
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

	if claims[s.UserIDClaim] == nil {
		// No USERID_CLAIM, pass this authenticator
		logger.Error("USERID_CLAIM doesn't exist in the id token")
		return nil, false, nil
	}

	groups := []string{}
	groupsClaim := claims[s.GroupsClaim]
	if groupsClaim != nil {
		groups = common.InterfaceSliceToStringSlice(groupsClaim.([]interface{}))
	}

	// Authentication using header successfully completed
	extra := map[string][]string{"auth-method": {"header"}}

	resp := &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   claims[s.UserIDClaim].(string),
			Groups: groups,
			Extra:  extra,
		},
	}
	return resp, true, nil
}
