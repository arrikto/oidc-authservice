// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/tevino/abool"
	"github.com/yosssi/boltstore/shared"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	clientconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

// Issue: https://github.com/gorilla/sessions/issues/200
const secureCookieKeyPair = "notNeededBecauseCookieValueIsRandom"

func main() {

	c, err := parseConfig()
	if err != nil {
		log.Fatalf("Failed to parse configuration: %+v", err)
	}
	log.Infof("Config: %+v", c)

	// Start readiness probe immediately
	log.Infof("Starting readiness probe at %v", c.ReadinessProbePort)
	isReady := abool.New()
	go func() {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", c.ReadinessProbePort), readiness(isReady)))
	}()

	/////////////////////////////////////////////////////
	// Start server immediately for whitelisted routes //
	/////////////////////////////////////////////////////

	s := &server{}

	// Register handlers for routes
	router := mux.NewRouter()
	router.HandleFunc(path.Join(c.AuthserviceURLPrefix.Path, OIDCCallbackPath), s.callback).Methods(http.MethodGet)
	router.HandleFunc(path.Join(c.AuthserviceURLPrefix.Path, SessionLogoutPath), s.logout).Methods(http.MethodPost)

	router.PathPrefix("/").Handler(whitelistMiddleware(c.SkipAuthURLs, isReady)(http.HandlerFunc(s.authenticate)))

	// Start server
	log.Infof("Starting server at %v:%v", c.Hostname, c.Port)
	stopCh := make(chan struct{})
	go func(stopCh chan struct{}) {
		log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", c.Hostname, c.Port), handlers.CORS()(router)))
		close(stopCh)
	}(stopCh)

	// Start web server
	webServer := WebServer{
		TemplatePaths: c.TemplatePath,
		ProviderURL:   c.ProviderURL.String(),
		ClientName:    c.ClientName,
		ThemeURL:      resolvePathReference(c.ThemesURL, c.Theme).String(),
		Frontend:      c.UserTemplateContext,
	}
	log.Infof("Starting web server at %v:%v", c.Hostname, c.WebServerPort)
	go func() {
		log.Fatal(webServer.Start(fmt.Sprintf("%s:%d", c.Hostname, c.WebServerPort)))
	}()

	/////////////////////////////////
	// Resume setup asynchronously //
	/////////////////////////////////

	// Read custom CA bundle
	var caBundle []byte
	if c.CABundlePath != "" {
		caBundle, err = ioutil.ReadFile(c.CABundlePath)
		if err != nil {
			log.Fatalf("Could not read CA bundle path %s: %v", c.CABundlePath, err)
		}
	}

	// OIDC Discovery
	var provider *oidc.Provider
	ctx := setTLSContext(context.Background(), caBundle)
	for {
		provider, err = oidc.NewProvider(ctx, c.ProviderURL.String())
		if err == nil {
			break
		}
		log.Errorf("OIDC provider setup failed, retrying in 10 seconds: %v", err)
		time.Sleep(10 * time.Second)
	}

	endpoint := provider.Endpoint()
	if len(c.OIDCAuthURL.String()) > 0 {
		endpoint.AuthURL = c.OIDCAuthURL.String()
	}

	// Setup session store
	// Using BoltDB by default
	store, err := newBoltDBSessionStore(c.SessionStorePath,
		shared.DefaultBucketName, false)
	if err != nil {
		log.Fatalf("Error creating session store: %v", err)
	}
	defer store.Close()

	// Setup state store
	// Using BoltDB by default
	oidcStateStore, err := newBoltDBSessionStore(c.OIDCStateStorePath,
		"oidc_state", true)
	if err != nil {
		log.Fatalf("Error creating oidc state store: %v", err)
	}
	defer oidcStateStore.Close()

	// Get Kubernetes authenticator
	restConfig, err := clientconfig.GetConfig()
	if err != nil {
		log.Fatalf("Error getting K8s config: %v", err)
	}
	k8sAuthenticator, err := newKubernetesAuthenticator(restConfig, c.Audiences)
	if err != nil {
		log.Fatalf("Error creating K8s authenticator: %v", err)
	}

	// Get OIDC Session Authenticator
	oauth2Config := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  c.RedirectURL.String(),
		Scopes:       c.OIDCScopes,
	}

	sessionAuthenticator := &sessionAuthenticator{
		store:                   store,
		cookie:                  userSessionCookie,
		header:                  c.AuthHeader,
		strictSessionValidation: c.StrictSessionValidation,
		caBundle:                caBundle,
		provider:                provider,
		oauth2Config:            oauth2Config,
	}

	groupsAuthorizer := newGroupsAuthorizer(c.GroupsAllowlist)

	idTokenAuthenticator := &idTokenAuthenticator{
		header:      c.IDTokenHeader,
		caBundle:    caBundle,
		provider:    provider,
		clientID:    c.ClientID,
		userIDClaim: c.UserIDClaim,
		groupsClaim: c.GroupsClaim,
	}

	// Set the server values.
	// The isReady atomic variable should protect it from concurrency issues.

	*s = server{
		provider:     provider,
		oauth2Config: oauth2Config,
		// TODO: Add support for Redis
		store:                  store,
		oidcStateStore:         oidcStateStore,
		afterLoginRedirectURL:  c.AfterLoginURL.String(),
		homepageURL:            c.HomepageURL.String(),
		afterLogoutRedirectURL: c.AfterLogoutURL.String(),
		idTokenOpts: jwtClaimOpts{
			userIDClaim: c.UserIDClaim,
			groupsClaim: c.GroupsClaim,
		},
		upstreamHTTPHeaderOpts: httpHeaderOpts{
			userIDHeader: c.UserIDHeader,
			userIDPrefix: c.UserIDPrefix,
			groupsHeader: c.GroupsHeader,
		},
		userIdTransformer:       c.UserIDTransformer,
		sessionMaxAgeSeconds:    c.SessionMaxAge,
		strictSessionValidation: c.StrictSessionValidation,
		sessionDomain:           c.SessionDomain,
		authHeader:              c.AuthHeader,
		caBundle:                caBundle,
		authenticators: []authenticator.Request{
			sessionAuthenticator,
			idTokenAuthenticator,
			k8sAuthenticator,
		},
		authorizers: []Authorizer{groupsAuthorizer},
	}
	switch c.SessionSameSite {
	case "None":
		s.sessionSameSite = http.SameSiteNoneMode
	case "Strict":
		s.sessionSameSite = http.SameSiteStrictMode
	default:
		// Use Lax mode as the default
		s.sessionSameSite = http.SameSiteLaxMode
	}

	// Setup complete, mark server ready
	isReady.Set()

	// Block until server exits
	<-stopCh
}
