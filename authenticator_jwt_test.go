package main

import (
	"testing"

)

func TestPerformLocalChecks(t *testing.T) {

	s := &jwtTokenAuthenticator {
		audiences: []string{
					"myaudience1",
					"myaudience2",
					"00af7fe8-a019-4859-94af-3d0f4009fed5",
				   },
		issuer:	   "https://auth.pingone.eu/e6b1425e-6090-4d29-a961-e760860d932a/as",
	}

	tests := []struct {
		testName    string
		bearerToken string
		success     bool
	}{
		{
			testName: "Non-parsable JWT",
			bearerToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHQifQewJ.ur9WEOCjuX6kJ2COJwz058hu1wlYUhs105x8vc-L8fEYFpOUVqWDuaoV-EU-1eThpHvDmGyIKYd4Jhffg",
			success: false,
		},
		{
			testName: "Wrong issuer",
			bearerToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHQifQ.eyJjbGllbnRfaWQiOiJkMDM4NjI3ZC0yOWYzLTQ4YzItOTBkNi1hN2QzOGU4YTdkNWMiLCJpc3MiOiJodHRwczovL2F1dGgucGluZ29uZS5ldS80MjY3ZGQ1MS1kMGJlLTQ2N2EtOTY4OS0zMmU3YzE0ZGU2YTgvYXMiLCJpYXQiOjE2NDkwNzYwNjksImV4cCI6MTY0OTA3OTY2OSwiYXVkIjpbIm15cmVzb3VyY2UyIl0sInNjb3BlIjoibXlUZXN0U2NvcGUyIn0.Tw8HFKKKnHG1-24cg2YCK92J7wmSIKSJDmUIjQvFidpK4xGNamTeVLro5UN5ZO8Y4WmXQQuLZ1nvB7aWu9M2Cm0R7N4wEZJjEv-u-hHTNzJb0e2PXZBRB3eXRnJ5wbUnWY5ABRiHcHK75KvNvGlhr9nUhID-u-auJ3VH5G-5kLvI4YMl2rMXuH5-KkkfNpTUe0iSZ2d4yvfSI6tp-_NY3l1Pc_1GRgKifgeRFTN0VsoLAghyzQaoqSmfKmv8aMLYFwK8tJHK5VP4BTvs6DPpy6kUYkhZKykaCistHLHn0VcnGNy9ZKFpQwc4FTgEhBHnPiUndmYZFiNonEZpiUj4dQ",
			success: false,
		},
		{
			testName: "Wrong audience",
			bearerToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHQifQ.eyJjbGllbnRfaWQiOiJkZDQxOGNkYS00Y2JjLTQ2NWUtYTM5OS1iODcwMzI0ZWU2NmEiLCJpc3MiOiJodHRwczovL2F1dGgucGluZ29uZS5ldS9lNmIxNDI1ZS02MDkwLTRkMjktYTk2MS1lNzYwODYwZDkzMmEvYXMiLCJpYXQiOjE2NDkwNzY0MTYsImV4cCI6MTY0OTA4MDAxNiwiYXVkIjpbIm15VGVzdFJlc291cmNlMiJdLCJzY29wZSI6Im15VGVzdFNjb3BlMiJ9.BwMsVbucqOZ3zOWbC_o5400aIs7G1wvlDDSbyv-yE6YEKpxd5fvgvcnWm483fEmPciJC0oZ7Uv8SG8kPvmYE4HavqT91jX2D7-d0CQrgJKPuIXKmmu3hdlxShsZ_7GG2hM4YcMN4xdxMC5mUncwKbHXgg7njp93tXVMl_eGxfNwh3m2xD8ay_DGkxURT3YNSzA_Nla9wi4fTC_42Bnq_s37--XFf88Ouegbkr6ZsH2j4OhplGzmPskivT-o20cw_cvi3slL0bdVpVIytIyOpAq-Q7X5OHSmOwA19QfR2Va1ZXDWoN5SBa7DG-N8rZ86pw2Qq_4R7Y52izjtyMXJdIg",
			success: false,
		},
		{
			testName: "Correct issuer and audience",
			bearerToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHQifQ.eyJpc3MiOiJodHRwczovL2F1dGgucGluZ29uZS5ldS9lNmIxNDI1ZS02MDkwLTRkMjktYTk2MS1lNzYwODYwZDkzMmEvYXMiLCJzdWIiOiIxYWRkNjk5MC0xNDRjLTRlYjQtOTllNy1iMTg5YzNkMWNiNTAiLCJhdWQiOiIwMGFmN2ZlOC1hMDE5LTQ4NTktOTRhZi0zZDBmNDAwOWZlZDUiLCJpYXQiOjE2NDkwNzMzMzgsImV4cCI6MTY0OTA3NjkzOCwiYWNyIjoiU2luZ2xlX0ZhY3RvciIsImFtciI6WyJwd2QiXSwiYXV0aF90aW1lIjoxNjQ5MDczMzM3LCJhdF9oYXNoIjoiNk9JazEybXN0aVlvYzNfRlFOMW1EQSIsInNpZCI6Ijg3NjcwYTNiLThlYTAtNDQ3OS1hNmY1LWUyMzUwMDBlMzJjZCIsImdyb3VwcyI6WyJteWdyb3VwIl0sInByZWZlcnJlZF91c2VybmFtZSI6ImF0aGFtYXJrQGFycmlrdG8uY29tIiwiZW52IjoiZTZiMTQyNWUtNjA5MC00ZDI5LWE5NjEtZTc2MDg2MGQ5MzJhIiwib3JnIjoiYTFmY2JkYjQtY2MwYS00Mzg3LWI3MzgtMTI4NTg3ZmYwNzYzIiwicDEucmVnaW9uIjoiRVUifQ.iGWCxEJv_2-FFlZMH35xYvl6qFTGXvrZNHKvUIVGbVIfQdt6fKzhpgIknWmtFs8hK9WW0b9Pt-MnclwQkgljtCwSLLh-s96KOnCKxXbSb7rfAd5Ef8B4Cd7q8rMd8qdxJgIbS3MRdH5UvE-ozU9gQdKpqC2R3zhX0jKsgdpLOIOqhBLaVy8rn2o8kPZL_R2M49HB9LVeYlqrbvY_I3noPedcQPybBLCpTv-oIIfQDENyyePGv_By-_O0CsYeKTLfPTxSIcAYGpywoJ8HcUov0l_7Uq0ej1xdXGYzt3Be3LInR2267JTTebi0OQEMgKZzFIkVxxvNuI9T8KkblrvoTw",
			success: true,
		},
	}

	for _, c := range tests {
		t.Run(c.testName, func(t *testing.T) {
			err:= s.performLocalChecks(c.bearerToken)

			success := true
			if err != nil {
				success = false
			}

			if success != c.success {
				t.Errorf("performLocalChecks result for %v is not the expected one. Error %v", c, err)
			}
		})
	}
}

func TestRetrieveUserIDGroupsClaims(t *testing.T) {

	s := &jwtTokenAuthenticator {
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
