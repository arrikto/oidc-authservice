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
	"github.com/arrikto/oidc-authservice/common"
	"github.com/arrikto/oidc-authservice/oidc"
	"github.com/arrikto/oidc-authservice/sessions"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/patrickmn/go-cache"
	"github.com/tevino/abool"
	"golang.org/x/oauth2"
	clientconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

const CacheCleanupInterval = 10

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
		log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", c.Hostname, c.Port), handlers.CORS()(router)))
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

	// OIDC Discovery
	ctx := common.SetTLSContext(context.Background(), caBundle)
	provider := oidc.NewProvider(ctx, c.ProviderURL)
	endpoint := provider.Endpoint()
	if len(c.OIDCAuthURL.String()) > 0 {
		endpoint.AuthURL = c.OIDCAuthURL.String()
	}

	// Setup session store and state store using the configured session store
	// type (BoltDB, or redis)
	store, oidcStateStore := sessions.InitiateSessionStores(c)

	defer store.Close()
	defer oidcStateStore.Close()

	// Get Kubernetes authenticator
	var k8sAuthenticator authenticators.AuthenticatorRequest
	restConfig, err := clientconfig.GetConfig()
	if err != nil && c.KubernetesAuthnEnabled {
		log.Fatalf("Error getting K8s config: %v", err)
	} else if err != nil {
		// If Kubernetes authenticator is disabled, ignore the error.
		log.Debugf("Error getting K8s config: %v. "+
			"Kubernetes authenticator is disabled, skipping ...", err)
	} else {
		k8sAuthenticator, err = authenticators.NewKubernetesAuthenticator(
			restConfig, c.Audiences)
		if err != nil && c.KubernetesAuthnEnabled {
			log.Fatalf("Error creating K8s authenticator: %v", err)
		} else if err != nil {
			// If Kubernetes authenticator is disabled, ignore the error.
			log.Debugf("Error creating K8s authenticator:: %v. "+
				"Kubernetes authenticator is disabled, skipping ...", err)
		}
	}

	// Get OIDC Session Authenticator
	oauth2Config := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  c.RedirectURL.String(),
		Scopes:       c.OIDCScopes,
	}

	// Setup authenticators.
	sessionAuthenticator := &authenticators.SessionAuthenticator{
		Store:                   store,
		Cookie:                  sessions.UserSessionCookie,
		Header:                  c.AuthHeader,
		StrictSessionValidation: c.StrictSessionValidation,
		CaBundle:                caBundle,
		Provider:                provider,
		Oauth2Config:            oauth2Config,
	}

	idTokenAuthenticator := &authenticators.IDTokenAuthenticator{
		Header:      c.IDTokenHeader,
		CaBundle:    caBundle,
		Provider:    provider,
		ClientID:    c.ClientID,
		UserIDClaim: c.UserIDClaim,
		GroupsClaim: c.GroupsClaim,
	}

	jwtTokenAuthenticator := &authenticators.JWTTokenAuthenticator{
		Header:      c.IDTokenHeader,
		CaBundle:    caBundle,
		Provider:    provider,
		Audiences:   c.Audiences,
		Issuer:      c.ProviderURL.String(),
		UserIDClaim: c.UserIDClaim,
		GroupsClaim: c.GroupsClaim,
	}

	opaqueTokenAuthenticator := &authenticators.OpaqueTokenAuthenticator{
		Header:       c.IDTokenHeader,
		CaBundle:     caBundle,
		Provider:     provider,
		Oauth2Config: oauth2Config,
		UserIDClaim:  c.UserIDClaim,
		GroupsClaim:  c.GroupsClaim,
	}

	// Set the bearerUserInfoCache cache to store
	// the (Bearer Token, UserInfo) pairs.
	bearerUserInfoCache := cache.New(time.Duration(c.CacheExpirationMinutes)*time.Minute, time.Duration(CacheCleanupInterval)*time.Minute)

	// Configure the authorizers.
	var authorizers []Authorizer

	// Add the groups' authorizer.
	groupsAuthorizer := newGroupsAuthorizer(c.GroupsAllowlist)
	authorizers = append(authorizers, groupsAuthorizer)

	// Add the external authorizer.
	if c.ExternalAuthzUrl != "" {
		externalAuthorizer := ExternalAuthorizer{c.ExternalAuthzUrl}
		authorizers = append(authorizers, externalAuthorizer)
	}

	// Set the server values.
	// The isReady atomic variable should protect it from concurrency issues.

	*s = server{
		provider:     provider,
		oauth2Config: oauth2Config,
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
		upstreamHTTPHeaderOpts: common.HTTPHeaderOpts{
			UserIDHeader:     c.UserIDHeader,
			UserIDPrefix:     c.UserIDPrefix,
			GroupsHeader:     c.GroupsHeader,
			AuthMethodHeader: c.AuthMethodHeader,
		},
		userIdTransformer:       c.UserIDTransformer,
		sessionMaxAgeSeconds:    c.SessionMaxAge,
		sessionHttpOnly:         c.SessionHttpOnly,
		sessionSecure:           c.SessionSecure,
		strictSessionValidation: c.StrictSessionValidation,
		cacheEnabled:            c.CacheEnabled,
		cacheExpirationMinutes:  c.CacheExpirationMinutes,
		IDTokenAuthnEnabled:     c.IDTokenAuthnEnabled,
		KubernetesAuthnEnabled:  c.KubernetesAuthnEnabled,
		AccessTokenAuthnEnabled: c.AccessTokenAuthnEnabled,
		AccessTokenAuthn:        c.AccessTokenAuthn,
		authHeader:              c.AuthHeader,
		caBundle:                caBundle,
		authenticators: []authenticators.AuthenticatorRequest{
			k8sAuthenticator,
			opaqueTokenAuthenticator,
			jwtTokenAuthenticator,
			sessionAuthenticator,
			idTokenAuthenticator,
		},
		authorizers: authorizers,
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

	// Setup complete, mark server ready
	isReady.Set()

	// Block until server exits
	<-stopCh
}
