// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"time"

	"github.com/arrikto/oidc-authservice/authenticators"
	"github.com/arrikto/oidc-authservice/authorizer"
	"github.com/arrikto/oidc-authservice/common"
	"github.com/arrikto/oidc-authservice/sessions"

	"github.com/gorilla/mux"
	"github.com/patrickmn/go-cache"
	"github.com/tevino/abool"
)

const CacheCleanupInterval = 10

func newConfigOrGroupsAuthorizer(c *common.Config) authorizer.Authorizer {
	log := common.StandardLogger()

	if c.AuthzConfigPath != "" {
		log.Infof("AuthzConfig file path=%s", c.AuthzConfigPath)
		authz, err := authorizer.NewConfigAuthorizer(c.AuthzConfigPath)
		if err != nil {
			log.Fatalf("Error creating configAuthorizer: %v", err)
		}

		return authz
	} else {
		log.Info("no AuthzConfig file specified, using basic groups authorizer")
		return authorizer.NewGroupsAuthorizer(c.GroupsAllowlist)
	}
}

func main() {
	log := common.StandardLogger()

	c, err := common.ParseConfig()
	if err != nil {
		log.Fatalf("Failed to parse configuration: %+v", err)
	}
	log.Infof("Config: %+v", c)

	// Set log level
	common.SetLogLevel(c.LogLevel)

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
	router.HandleFunc(c.RedirectURL.Path, s.callback).Methods(http.MethodGet)
	router.HandleFunc(path.Join(c.AuthserviceURLPrefix.Path, SessionLogoutPath), s.logout).Methods(http.MethodPost)

	router.PathPrefix(c.VerifyAuthURL.Path).Handler(s.whitelistMiddleware(c.SkipAuthURLs, isReady, true)(http.HandlerFunc(s.authenticate_no_login))).Methods(http.MethodGet)
	router.PathPrefix("/").Handler(s.whitelistMiddleware(c.SkipAuthURLs, isReady, false)(http.HandlerFunc(s.authenticate_or_login)))

	// Start judge server
	log.Infof("Starting judge server at %v:%v", c.Hostname, c.Port)
	stopCh := make(chan struct{})
	go func(stopCh chan struct{}) {
		log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", c.Hostname, c.Port), router))
		close(stopCh)
	}(stopCh)

	// Start web server
	webServer := WebServer{
		TemplatePaths: c.TemplatePath,
		ProviderURL:   c.ProviderURL.String(),
		ClientName:    c.ClientName,
		ThemeURL:      common.ResolvePathReference(c.ThemesURL, c.Theme).String(),
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

	// Setup session store and state store using the configured session store
	// type (BoltDB, or redis)
	store, oidcStateStore := sessions.InitiateSessionStores(c)

	defer store.Close()
	defer oidcStateStore.Close()

	// Get Kubernetes authenticator
	k8sAuthenticator, err := authenticators.NewKubernetesAuthenticator(c.Audiences)
	if err != nil && c.KubernetesAuthnEnabled {
		log.Fatalf("Error creating K8s authenticator: %v", err)
	} else {
		// If Kubernetes authenticator is disabled, ignore the error.
		log.Debugf("%v. Kubernetes authenticator is disabled, skipping ...", err)
	}

	tlsCfg := common.TlsConfig(caBundle)

	sessionManager := sessions.NewSessionManager(
		tlsCfg.Context(context.Background()),
		c.ClientID,
		c.ClientSecret,
		c.ProviderURL,
		c.OIDCAuthURL,
		c.RedirectURL,
		c.OIDCScopes,
	)

	// Setup authenticators.
	sessionAuthenticator := authenticators.NewSessionAuthenticator(
		store,
		sessions.UserSessionCookie,
		c.TokenHeader,
		c.TokenScheme,
		c.StrictSessionValidation,
		tlsCfg,
		sessionManager,
	)

	idTokenAuthenticator := authenticators.NewIDTokenAuthenticator(
		c.IDTokenHeader,
		c.UserIDClaim,
		c.GroupsClaim,
		tlsCfg,
		sessionManager,
	)

	jwtTokenAuthenticator := authenticators.NewJWTTokenAuthenticator(
		c.IDTokenHeader,
		c.Audiences,
		c.ProviderURL.String(),
		c.UserIDClaim,
		c.GroupsClaim,
		tlsCfg,
		sessionManager,
	)

	opaqueTokenAuthenticator := authenticators.NewOpaqueTokenAuthenticator(
		c.IDTokenHeader,
		c.UserIDClaim,
		c.GroupsClaim,
		tlsCfg,
		sessionManager,
	)

	// Set the bearerUserInfoCache cache to store
	// the (Bearer Token, UserInfo) pairs.
	bearerUserInfoCache := cache.New(time.Duration(c.CacheExpirationMinutes)*time.Minute, time.Duration(CacheCleanupInterval)*time.Minute)

	// Configure the authorizers.
	var authorizers []authorizer.Authorizer

	// Add the config or groups authorizer.
	configOrGroupsAuthorizer := newConfigOrGroupsAuthorizer(c)
	authorizers = append(authorizers, configOrGroupsAuthorizer)

	// Add the external authorizer.
	if c.ExternalAuthzUrl != "" {
		externalAuthorizer := authorizer.ExternalAuthorizer{c.ExternalAuthzUrl}
		authorizers = append(authorizers, externalAuthorizer)
	}

	// Set the server values.
	// The isReady atomic variable should protect it from concurrency issues.

	*s = server{
		// TODO: Add support for Redis
		store:                  store,
		oidcStateStore:         oidcStateStore,
		bearerUserInfoCache:    bearerUserInfoCache,
		afterLoginRedirectURL:  c.AfterLoginURL.String(),
		homepageURL:            c.HomepageURL.String(),
		afterLogoutRedirectURL: c.AfterLogoutURL.String(),
		verifyAuthURL:          c.VerifyAuthURL.String(),
		idTokenOpts: common.JWTClaimOpts{
			UserIDClaim: c.UserIDClaim,
			GroupsClaim: c.GroupsClaim,
		},
		userHeaderHelper: newUserHeaderHelper(
			common.HTTPHeaderOpts{
				UserIDHeader:     c.UserIDHeader,
				UserIDPrefix:     c.UserIDPrefix,
				GroupsHeader:     c.GroupsHeader,
				AuthMethodHeader: c.AuthMethodHeader,
			},
			&c.UserIDTransformer,
		),
		sessionMaxAgeSeconds:   c.SessionMaxAge,
		cacheEnabled:           c.CacheEnabled,
		cacheExpirationMinutes: c.CacheExpirationMinutes,

		IDTokenAuthnEnabled:     c.IDTokenAuthnEnabled,
		KubernetesAuthnEnabled:  c.KubernetesAuthnEnabled,
		AccessTokenAuthnEnabled: c.AccessTokenAuthnEnabled,
		AccessTokenAuthn:        c.AccessTokenAuthn,
		authenticators: []authenticators.Authenticator{
			k8sAuthenticator,
			opaqueTokenAuthenticator,
			jwtTokenAuthenticator,
			sessionAuthenticator,
			idTokenAuthenticator,
		},
		authorizers:    authorizers,
		tlsCfg:         tlsCfg,
		sessionManager: sessionManager,
		sessionDomain:  c.SessionDomain,
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

	// Print server configuration info
	log.Infof("Cache enabled: %t", s.cacheEnabled)

	s.newState = sessions.NewStateFunc(
		&sessions.Config{
			SessionDomain: c.SessionDomain,
			SchemeDefault: c.SchemeDefault,
			SchemeHeader:  c.SchemeHeader,
		},
	)

	// Setup complete, mark server ready
	isReady.Set()

	// Block until server exits
	<-stopCh
}
