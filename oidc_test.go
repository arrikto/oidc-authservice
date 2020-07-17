package main

import (
	"context"
	"html/template"
	"net/http"
	"testing"
	"time"

	"github.com/arrikto/oidc-authservice/pkg/common"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

func startFakeOIDCProvider(addr string) {

	discoveryDoc := `
	{
		"issuer": "{{.Address}}",
		"authorization_endpoint": "{{.Address}}/auth",
		"userinfo_endpoint": "{{.Address}}/userinfo",
		"revocation_endpoint": "{{.Address}}/revoke",
		"jwks_uri": "{{.Address}}/jwks",
		"response_types_supported": [
		 "code",
		 "token",
		 "id_token",
		 "code token",
		 "code id_token",
		 "token id_token",
		 "code token id_token",
		 "none"
		],
		"subject_types_supported": [
		 "public"
		],
		"id_token_signing_alg_values_supported": [
		 "RS256"
		],
		"scopes_supported": [
		 "openid",
		 "email",
		 "profile"
		],
		"token_endpoint_auth_methods_supported": [
		 "client_secret_post",
		 "client_secret_basic"
		],
		"claims_supported": [
		 "aud",
		 "email",
		 "email_verified",
		 "exp",
		 "family_name",
		 "given_name",
		 "iat",
		 "iss",
		 "locale",
		 "name",
		 "picture",
		 "sub"
		],
		"code_challenge_methods_supported": [
		 "plain",
		 "S256"
		],
		"grant_types_supported": [
		 "authorization_code",
		 "refresh_token",
		 "urn:ietf:params:oauth:grant-type:device_code",
		 "urn:ietf:params:oauth:grant-type:jwt-bearer"
		]
	   }
	`

	tmpl, err := template.New("oidc_discovery_doc").Parse(discoveryDoc)
	if err != nil {
		log.Fatalf("Error parsing discovery doc template: %v", err)
	}

	discoveryHandler := func(w http.ResponseWriter, r *http.Request) {
		err := tmpl.Execute(w, struct{ Address string }{Address: addr})
		if err != nil {
			log.Errorf("Error executing oidc discovery doc template: %v", err)
		}
	}

	userinfoHandler := func(w http.ResponseWriter, r *http.Request) {
		log.Info("Userinfo handler, returning 401...")
		w.WriteHeader(http.StatusUnauthorized)
	}

	router := mux.NewRouter()
	router.HandleFunc("/.well-known/openid-configuration", discoveryHandler)
	router.HandleFunc("/userinfo", userinfoHandler)
	log.Infof("Starting fake OIDC Provider at address: %v", addr)
	if err := http.ListenAndServe("localhost:9999", router); err != nil {
		log.Fatalf("Error in fake OIDC Provider server: %v", err)
	}
}

func TestGetUserInfo_ContextCancelled(t *testing.T) {

	// Start fake OIDC provider
	oidcProviderAddr := "http://localhost:9999"
	go startFakeOIDCProvider(oidcProviderAddr)
	time.Sleep(5 * time.Second)
	provider, err := oidc.NewProvider(context.Background(), oidcProviderAddr)
	if err != nil {
		t.Fatalf("Error creating OIDC Provider: %v", err)
	}

	// Make a UserInfo request
	_, err = GetUserInfo(context.Background(), provider,
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"}))

	// Check that we find a wrapped requestError
	var reqErr *common.RequestError
	if !errors.As(err, &reqErr) {
		log.Fatalf("Returned error is not a requestError. Got: %+v", reqErr)
	}

	if reqErr.Response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Got wrong status code. Got '%v', expected '%v'.",
			reqErr.Response.StatusCode, http.StatusUnauthorized)
	}
}
