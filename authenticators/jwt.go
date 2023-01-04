package authenticators

import (
	"net/http"
	"strings"
	"encoding/json"
	"fmt"

	"github.com/arrikto/oidc-authservice/common"
	"github.com/arrikto/oidc-authservice/oidc"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	audienceNotfound = "oidc: expected audience"
)

type JWTTokenAuthenticator struct {
	Header      string // header name where JWT access token is stored
	CaBundle    []byte
	Provider    oidc.Provider
	Audiences   []string // need client id to verify the id token
	Issuer      string // need this for the local check
	UserIDClaim string // retrieve the userid if the claim exists
	GroupsClaim string
}

type jwtLocalChecks struct {
	Issuer    string          `json:"iss"`
	Audiences common.Audience `json:"aud"`
}

func (s *JWTTokenAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := common.LoggerForRequest(r, "JWT access token authenticator")

	// Get JWT access token from header
	bearer := common.GetBearerToken(r.Header.Get(s.Header))
	if len(bearer) == 0 {
		logger.Info("No bearer token found")
		return nil, false, nil
	}

	ctx := common.SetTLSContext(r.Context(), s.CaBundle)

	// Verifying received JWT token
	for _, aud := range s.Audiences {
		verifier := s.Provider.Verifier(oidc.NewConfig(aud))
		token, err := verifier.Verify(ctx, bearer)

		if err != nil {

			errorMessage := err.Error()
			if strings.Contains(errorMessage, audienceNotfound) {
				continue
			}


			// If a local check fails then AuthService will test
			// the rest of the available authentication methods.
			if localErr := s.performLocalChecks(bearer); localErr != nil {
				logger.Errorf("JWT-token verification is not the appropriate" +
							" authentication method for the received request.")
				return nil, false, localErr
			}

			// Return the error of the go-oidc ID token verifier.
			logger.Errorf("JWT-token verification failed: %v", err)
			return nil, false, &common.AuthenticatorSpecificError{Err: err}
		}

		// Retrieve the USERID_CLAIM and the GROUPS_CLAIM
		var claims map[string]interface{}
		if claimErr := token.Claims(&claims); claimErr != nil {
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

	audienceErr := fmt.Errorf("JWT-token verification failed for all the configured audiences")
	return nil, false, audienceErr

}

// Perform local checks for the issuer and the audiences
func (s *JWTTokenAuthenticator) performLocalChecks(bearer string) (error){

	// Verify that the retrieved Bearer token is a parsable JWT token
	payload, localErr := common.ParseJWT(bearer)
	if localErr != nil { // Check next authenticator
		localErr = fmt.Errorf("Could not parse the inspected Bearer token.")
		return localErr
	}

	// Retrieve issuer and the audience claims
	var tokenLocalChecks jwtLocalChecks
	if localErr = json.Unmarshal(payload, &tokenLocalChecks); localErr != nil { // Check next authenticator
		localErr = fmt.Errorf("Could not retrieve the \"issuer\" and the \"audience\" claims" +
					" from the Bearer Token.")
		return localErr
	}

	// Check issuer
	if tokenLocalChecks.Issuer != s.Issuer { // Check next authenticator
		localErr = fmt.Errorf("The retrieved \"iss\" did not match the expected one.")
		return localErr
	}

	// Check audiences
	if !common.Contains(s.Audiences, tokenLocalChecks.Audiences){ // Check next authenticator
		localErr = fmt.Errorf("The retrieved \"aud\" did not match with any of the" +
					" expected audiences.")
		return localErr
	}

	// Local checks succeeded.
	return nil

}

// Retrieve the USERID_CLAIM and the GROUPS_CLAIM from the JWT access token
func (s *JWTTokenAuthenticator) retrieveUserIDGroupsClaims(claims map[string]interface{}) (string, []string, error){

		if claims[s.UserIDClaim] == nil {
			claimErr := fmt.Errorf("USERID_CLAIM not found in the JWT token")
			return "", []string{}, claimErr
		}

		groups := []string{}
		groupsClaim := claims[s.GroupsClaim]
		if groupsClaim == nil {
			claimErr := fmt.Errorf("GROUPS_CLAIM not found in the JWT token")
			return "", []string{}, claimErr
		}

		groups = common.InterfaceSliceToStringSlice(groupsClaim.([]interface{}))

		return claims[s.UserIDClaim].(string), groups, nil
}