package main

import (
	"testing"
)

func TestValidAccessTokenAuthn(t *testing.T) {

	tests := []struct {
		testName string
		AccessTokenAuthnEnabled bool
		AccessTokenAuthn string
		success  bool
	}{
		{
			testName: "Access Token Authenticator is set to JWT",
			AccessTokenAuthnEnabled: true,
			AccessTokenAuthn: "jwt",
			success: true,
		},
		{
			testName: "Access Token Authenticator is set to opaque",
			AccessTokenAuthnEnabled: true,
			AccessTokenAuthn: "opaque",
			success: true,
		},
		{
			testName: "Access Token Authenticator is disabled",
			AccessTokenAuthnEnabled: false,
			AccessTokenAuthn: "whatever",
			success: true,
		},
		{
			testName: "Access Token Authenticator envvar is invalid (JWT)",
			AccessTokenAuthnEnabled: true,
			AccessTokenAuthn: "JWT",
			success: false,
		},
		{
			testName: "Access Token Authenticator envvar is invalid (Opaque)",
			AccessTokenAuthnEnabled: true,
			AccessTokenAuthn: "Opaque",
			success: false,
		},
	}

	for _, c := range tests {
		t.Run(c.testName, func(t *testing.T) {
			result := validAccessTokenAuthn(c.AccessTokenAuthnEnabled, c.AccessTokenAuthn)

			if result != c.success {
				t.Errorf("validAccessTokenAuthn result for %v is not the expected one.", c)
			}
		})
	}
}

func TestRetrieveUserIDGroupsUserInfo(t *testing.T) {

	s := &opaqueTokenAuthenticator {
		userIDClaim: "preferred_username",
		groupsClaim: "groups",
	}

	tests := []struct {
		testName string
		claims   map[string]interface{}
		success  bool
	}{
		{
			testName: "No claims",
			claims: map[string]interface{}{},
			success: false,
		},
		{
			testName: "No USERID_CLAIM found",
			claims: map[string]interface{}{
				"bacon": "delicious",
				"eggs": struct {
				  source string
				  price  float64
				}{"chicken", 1.75},
				"steak": true,
			  },
			success: false,
		},
		{
			testName: "No GROUPS_CLAIM found",
			claims: map[string]interface{}{
				"preferred_username": "myusername",
			  },
			success: false,
		},
		{
			testName: "Both USERID_CLAIM and GROUPS_CLAIM exist",
			claims: map[string]interface{}{
				"preferred_username": "myusername",
				"groups": []interface{}{
					"mygroup",
					"Strokes",
				},
			  },
			success: true,
		},
	}

	for _, c := range tests {
		t.Run(c.testName, func(t *testing.T) {
			_, _, err:= s.retrieveUserIDGroupsClaims(c.claims)

			success := true
			if err != nil {
				success = false
			}

			if success != c.success {
				t.Errorf("retrieveUserIDGroupsClaims result for %v is not the expected one. Error %v", c, err)
			}
		})
	}
}
