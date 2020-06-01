package main

import (
	"os"
	"testing"
)

func TestParseConfig(t *testing.T) {
	envs := map[string]string{
		"OIDC_PROVIDER":          "example.local",
		"CLIENT_ID":              "example_client",
		"CLIENT_SECRET":          "example_secret",
		"AUTHSERVICE_URL_PREFIX": "/authservice/",
	}

	for k, v := range envs {
		if err := os.Setenv(k, v); err != nil {
			t.Fatalf("Failed to set env `%s' to `%s'", k, v)
		}
	}
	_, err := parseConfig()
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}
}
