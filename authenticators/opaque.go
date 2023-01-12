package authenticators

import (
	"net/http"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type OpaqueTokenAuthenticator struct {
	Header        string // header name where opaque access token is stored
	CaBundle      []byte
	Provider      oidc.Provider
	Oauth2Config  *oauth2.Config
	UserIDClaim   string // retrieve the userid claim
	GroupsClaim   string // retrieve the groups claim
}

func (s *OpaqueTokenAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := common.RequestLogger(r, "opaque access token authenticator")

	// get id-token from header
	bearer := common.GetBearerToken(r.Header.Get(s.Header))
	if len(bearer) == 0 {
		logger.Debug("No bearer token found")
		return nil, false, nil
	}

	opaque := &oauth2.Token {
		AccessToken: bearer,
		TokenType: "Bearer",
	}

	ctx := common.SetTLSContext(r.Context(), s.CaBundle)

	userInfo, err := oidc.GetUserInfo(ctx, s.Provider, s.Oauth2Config.TokenSource(ctx, opaque))
	if err != nil {
		var reqErr *common.RequestError
		if !errors.As(err, &reqErr) {
			return nil, false, errors.Wrap(err, "UserInfo request failed unexpectedly")
		}

		return nil, false, errors.Wrapf(err, "UserInfo request failed with code '%d'", reqErr.Response.StatusCode)
	}

	// Retrieve the USERID_CLAIM and the GROUPS_CLAIM
	var claims map[string]interface{}
	if claimErr := userInfo.Claims(&claims); claimErr != nil {
		logger.Errorf("Retrieving user claims failed: %v", claimErr)
		return nil, false, &common.AuthenticatorSpecificError{Err: claimErr}
	}

	userID, groups, claimErr := s.retrieveUserIDGroupsClaims(claims)
	if claimErr != nil {
		return nil, false, &common.AuthenticatorSpecificError{Err: claimErr}
	}

	// Authentication using header successfully completed
	extra := map[string][]string{"auth-method": {"header"}}

	resp := &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   userID,
			Groups: groups,
			Extra:  extra,
		},
	}
	return resp, true, nil
}

// Retrieve the USERID_CLAIM and the GROUPS_CLAIM from the /userinfo response
func (s *OpaqueTokenAuthenticator) retrieveUserIDGroupsClaims(claims map[string]interface{}) (string, []string, error){

	if claims[s.UserIDClaim] == nil {
		claimErr := errors.New("USERID_CLAIM not found in the response of the userinfo endpoint")
		return "", []string{}, claimErr
	}

	groups := []string{}
	groupsClaim := claims[s.GroupsClaim]
	if groupsClaim == nil {
		claimErr := errors.New("GROUPS_CLAIM not found in the response of the userinfo endpoint")
		return "", []string{}, claimErr
	}

	groups = common.InterfaceSliceToStringSlice(groupsClaim.([]interface{}))

	return claims[s.UserIDClaim].(string), groups, nil
}

// The Opaque Access Token Authenticator implements the Cacheable
// interface with the getCacheKey().
func (s *OpaqueTokenAuthenticator) GetCacheKey(r *http.Request) (string) {
	return common.GetBearerToken(r.Header.Get("Authorization"))

}