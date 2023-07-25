package authenticators

import (
	"testing"
)

func TestRetrieveUserIDGroupsUserInfo(t *testing.T) {

	s := &OpaqueTokenAuthenticator {
		UserIDClaim: "preferred_username",
		GroupsClaim: "groups",
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
