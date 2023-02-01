package main

import (
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type opaqueTokenAuthenticator struct {
	header        string // header name where opaque access token is stored
	caBundle      []byte
	provider      *oidc.Provider
	oauth2Config  *oauth2.Config
	userIDClaim   string // retrieve the userid claim
	groupsClaim   string // retrieve the groups claim
}

func (s *opaqueTokenAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := loggerForRequest(r, "opaque access token authenticator")

	// get id-token from header
	bearer := getBearerToken(r.Header.Get(s.header))
	if len(bearer) == 0 {
		logger.Info("No bearer token found")
		return nil, false, nil
	}

	opaque := &oauth2.Token {
		AccessToken: bearer,
		TokenType: "Bearer",
	}

	ctx := setTLSContext(r.Context(), s.caBundle)

	userInfo, err := GetUserInfo(ctx, s.provider, s.oauth2Config.TokenSource(ctx, opaque), logger)
	if err != nil {
		var reqErr *requestError
		if !errors.As(err, &reqErr) {
			return nil, false, errors.Wrap(err, "UserInfo request failed unexpectedly")
		}

		return nil, false, errors.Wrapf(err, "UserInfo request failed with code '%d'", reqErr.Response.StatusCode)
	}

	// Retrieve the USERID_CLAIM and the GROUPS_CLAIM
	var claims map[string]interface{}
	if claimErr := userInfo.Claims(&claims); claimErr != nil {
		logger.Errorf("Retrieving user claims failed: %v", claimErr)
		return nil, false, &authenticatorSpecificError{Err: claimErr}
	}

	userID, groups, claimErr := s.retrieveUserIDGroupsClaims(claims)
	if claimErr != nil {
		return nil, false, &authenticatorSpecificError{Err: claimErr}
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
func (s *opaqueTokenAuthenticator) retrieveUserIDGroupsClaims(claims map[string]interface{}) (string, []string, error){

	if claims[s.userIDClaim] == nil {
		claimErr := errors.New("USERID_CLAIM not found in the response of the userinfo endpoint")
		return "", []string{}, claimErr
	}

	groups := []string{}
	groupsClaim := claims[s.groupsClaim]
	if groupsClaim == nil {
		claimErr := errors.New("GROUPS_CLAIM not found in the response of the userinfo endpoint")
		return "", []string{}, claimErr
	}

	groups = interfaceSliceToStringSlice(groupsClaim.([]interface{}))

	return claims[s.userIDClaim].(string), groups, nil
}

// The Opaque Access Token Authenticator implements the Cacheable
// interface with the getCacheKey().
func (s *opaqueTokenAuthenticator) getCacheKey(r *http.Request) (string) {
	return getBearerToken(r.Header.Get("Authorization"))

}