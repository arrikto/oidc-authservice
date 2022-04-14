package main

import (
	"net/http"
	"strings"
	"encoding/json"
	"fmt"

	oidc "github.com/coreos/go-oidc"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	audienceNotfound = "oidc: expected audience"
)

type jwtTokenAuthenticator struct {
	header      string // header name where JWT access token is stored
	caBundle    []byte
	provider    *oidc.Provider
	audiences   []string // need client id to verify the id token
	issuer		string // need this for the local check
	userIDClaim string // retrieve the userid if the claim exists
	groupsClaim string
}

type jwtLocalChecks struct {
	Issuer    string   `json:"iss"`
	Audiences audience `json:"aud"`
}

func (s *jwtTokenAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := loggerForRequest(r, "JWT access token authenticator")

	// Get JWT access token from header
	bearer := getBearerToken(r.Header.Get(s.header))
	if len(bearer) == 0 {
		logger.Info("No bearer token found")
		return nil, false, nil
	}

	ctx := setTLSContext(r.Context(), s.caBundle)

	// Verifying received JWT token
	for _, aud := range s.audiences {
		verifier := s.provider.Verifier(&oidc.Config{ClientID: aud})
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
			return nil, false, &authenticatorSpecificError{Err: err}
		}

		// Retrieve the USERID_CLAIM and the GROUPS_CLAIM
		var claims map[string]interface{}
		if claimErr := token.Claims(&claims); claimErr != nil {
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

	audienceErr := fmt.Errorf("JWT-token verification failed for all the configured audiences")
	return nil, false, audienceErr

}

// Perform local checks for the issuer and the audiences 
func (s *jwtTokenAuthenticator) performLocalChecks(bearer string) (error){

	// Verify that the retrieved Bearer token is a parsable JWT token
	payload, localErr := parseJWT(bearer)
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
	if tokenLocalChecks.Issuer != s.issuer { // Check next authenticator
		localErr = fmt.Errorf("The retrieved \"iss\" did not match the expected one.")
		return localErr
	}

	// Check audiences
	if !contains(s.audiences, tokenLocalChecks.Audiences){ // Check next authenticator
		localErr = fmt.Errorf("The retrieved \"aud\" did not match with any of the" +
					" expected audiences.")
		return localErr
	}

	// Local checks succeeded. 
	return nil

}

// Retrieve the USERID_CLAIM and the GROUPS_CLAIM from the JWT access token
func (s *jwtTokenAuthenticator) retrieveUserIDGroupsClaims(claims map[string]interface{}) (string, []string, error){
		
		if claims[s.userIDClaim] == nil { 
			claimErr := fmt.Errorf("USERID_CLAIM not found in the JWT token")
			return "", []string{}, claimErr
		}

		groups := []string{}
		groupsClaim := claims[s.groupsClaim]
		if groupsClaim == nil {
			claimErr := fmt.Errorf("GROUPS_CLAIM not found in the JWT token")
			return "", []string{}, claimErr
		}

		groups = interfaceSliceToStringSlice(groupsClaim.([]interface{}))

		return claims[s.userIDClaim].(string), groups, nil
}