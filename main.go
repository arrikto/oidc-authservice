// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/arrikto/oidc-authservice/authenticator"
	"github.com/arrikto/oidc-authservice/authorizer"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/arrikto/oidc-authservice/svc"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/tevino/abool"
	"github.com/yosssi/boltstore/shared"
)

func newAuthorizer(c *config) authorizer.Authorizer {
	if c.AuthzConfigPath != "" {
		log.Infof("AuthzConfig file path=%s", c.AuthzConfigPath)
		return authorizer.NewConfigAuthorizer(c.AuthzConfigPath)
	} else {
		log.Info("no AuthzConfig file specified, using basic groups authorizer")
		return authorizer.NewGroupsAuthorizer(c.GroupsAllowlist)
	}
}

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

	enabledAuthenticators := map[string]bool{}
	for _, authenticator := range c.Authenticators {
		enabledAuthenticators[authenticator] = true
	}

	authenticators := []authenticator.Authenticator{}

	if enabledAuthenticators["kubernetes"] {
		k8sAuthenticator, err := authenticator.NewKubernetesAuthenticator(c.Audiences)
		if err != nil {
			log.Fatalf("Error creating K8s authenticator: %v", err)
		}

		authenticators = append(authenticators, k8sAuthenticator)
	}

	tlsCfg := svc.TlsConfig(caBundle)

	sessionManager := oidc.NewSessionManager(
		tlsCfg.Context(context.Background()),
		c.ClientID,
		c.ClientSecret,
		c.ProviderURL,
		c.OIDCAuthURL,
		c.RedirectURL,
		c.OIDCScopes,
	)

	sessionStore := oidc.NewSessionStore(
		store,
		c.AuthHeader,
		oidc.UserSessionCookie,
		c.UserIDClaim,
		c.GroupsClaim,
		c.SessionMaxAge,
		c.SessionSameSite,
	)

	if enabledAuthenticators["session"] {
		sessionAuthenticator := authenticator.NewSessionAuthenticator(
			sessionStore,
			c.StrictSessionValidation,
			tlsCfg,
			sessionManager,
		)
		authenticators = append(authenticators, sessionAuthenticator)
	}

	if enabledAuthenticators["idtoken"] {
		idTokenAuthenticator := authenticator.NewIdTokenAuthenticator(
			c.IDTokenHeader,
			c.UserIDClaim,
			c.GroupsClaim,
			sessionManager,
			tlsCfg,
		)
		authenticators = append(authenticators, idTokenAuthenticator)
	}

	// Set the server values.
	// The isReady atomic variable should protect it from concurrency issues.

	*s = server{
		// TODO: Add support for Redis
		sessionStore:           sessionStore,
		oidcStateStore:         oidc.NewOidcStateStore(oidcStateStore),
		afterLoginRedirectURL:  c.AfterLoginURL.String(),
		homepageURL:            c.HomepageURL.String(),
		afterLogoutRedirectURL: c.AfterLogoutURL.String(),
		upstreamHTTPHeaderOpts: httpHeaderOpts{
			userIDHeader: c.UserIDHeader,
			userIDPrefix: c.UserIDPrefix,
			groupsHeader: c.GroupsHeader,
		},
		userIdTransformer: c.UserIDTransformer,
		authenticators:    authenticators,
		authorizers:       []authorizer.Authorizer{newAuthorizer(c)},
		tlsCfg:            tlsCfg,
		sessionManager:    sessionManager,
	}

	// Setup complete, mark server ready
	isReady.Set()

	// Block until server exits
	<-stopCh
}
