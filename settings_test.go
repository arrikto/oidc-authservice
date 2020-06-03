package main

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestParseConfig(t *testing.T) {
	envs := map[string]string{
		// Compulsory
		"OIDC_PROVIDER":          "example.local",
		"CLIENT_ID":              "example_client",
		"CLIENT_SECRET":          "example_secret",
		"AUTHSERVICE_URL_PREFIX": "/authservice/",
		// Optional
		"REDIRECT_URL":     "http://redirect.example.com",
		"AFTER_LOGIN_URL":  "http://afterlogin.example.com",
		"AFTER_LOGOUT_URL": "http://afterlogout.example.com",
	}

	for k, v := range envs {
		if err := os.Setenv(k, v); err != nil {
			t.Fatalf("Failed to set env `%s' to `%s'", k, v)
		}
	}
	c, err := parseConfig()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}
	require.Equal(t, envs["REDIRECT_URL"], c.RedirectURL.String())
	require.Equal(t, envs["AFTER_LOGIN_URL"], c.AfterLoginURL.String())
	require.Equal(t, envs["AFTER_LOGOUT_URL"], c.AfterLogoutURL.String())
}
