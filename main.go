package main

import (
	"context"
	"github.com/boltdb/bolt"
	"github.com/coreos/go-oidc"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	log "github.com/sirupsen/logrus"
	"github.com/yosssi/boltstore/reaper"
	"github.com/yosssi/boltstore/store"
	"golang.org/x/oauth2"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Option Defaults
const (
	defaultHealthServerPort  = "8081"
	defaultServerHostname    = ""
	defaultServerPort        = "8080"
	defaultUserIDHeader      = "kubeflow-userid"
	defaultUserIDTokenHeader = "kubeflow-userid-token"
	defaultUserIDPrefix      = ""
	defaultUserIDClaim       = "email"
	defaultSessionMaxAge     = "86400"
)

// Issue: https://github.com/gorilla/sessions/issues/200
const secureCookieKeyPair = "notNeededBecauseCookieValueIsRandom"

type server struct {
	provider             *oidc.Provider
	oauth2Config         *oauth2.Config
	store                sessions.Store
	whitelist            []string
	staticDestination    string
	sessionMaxAgeSeconds int
	userIDOpts
}

type userIDOpts struct {
	header      string
	tokenHeader string
	prefix      string
	claim       string
}

func main() {

	// Start readiness probe immediately
	log.Infof("Starting readiness probe at %v", defaultHealthServerPort)
	isReady := &atomic.Value{}
	isReady.Store(false)
	go func() {
		log.Fatal(http.ListenAndServe(":"+defaultHealthServerPort, http.HandlerFunc(readiness(isReady))))
	}()

	/////////////
	// Options //
	/////////////

	// OIDC Provider
	providerURL := getURLEnvOrDie("OIDC_PROVIDER")
	authURL := os.Getenv("OIDC_AUTH_URL")
	// OIDC Client
	oidcScopes := clean(strings.Split(getEnvOrDie("OIDC_SCOPES"), " "))
	clientID := getEnvOrDie("CLIENT_ID")
	clientSecret := getEnvOrDie("CLIENT_SECRET")
	redirectURL := getURLEnvOrDie("REDIRECT_URL")
	staticDestination := os.Getenv("STATIC_DESTINATION_URL")
	whitelist := clean(strings.Split(os.Getenv("SKIP_AUTH_URI"), " "))
	// UserID Options
	userIDHeader := getEnvOrDefault("USERID_HEADER", defaultUserIDHeader)
	userIDTokenHeader := getEnvOrDefault("USERID_TOKEN_HEADER", defaultUserIDTokenHeader)
	userIDPrefix := getEnvOrDefault("USERID_PREFIX", defaultUserIDPrefix)
	userIDClaim := getEnvOrDefault("USERID_CLAIM", defaultUserIDClaim)
	// Server
	hostname := getEnvOrDefault("SERVER_HOSTNAME", defaultServerHostname)
	port := getEnvOrDefault("SERVER_PORT", defaultServerPort)
	// Store
	storePath := getEnvOrDie("STORE_PATH")
	// Sessions
	sessionMaxAge := getEnvOrDefault("SESSION_MAX_AGE", defaultSessionMaxAge)

	// OIDC Discovery
	var provider *oidc.Provider
	var err error
	for {
		provider, err = oidc.NewProvider(context.Background(), providerURL.String())
		if err == nil {
			break
		}
		log.Errorf("OIDC provider setup failed, retrying in 10 seconds: %v", err)
		time.Sleep(10 * time.Second)
	}

	endpoint := provider.Endpoint()
	if authURL != "" {
		endpoint.AuthURL = authURL
	}

	oidcScopes = append(oidcScopes, oidc.ScopeOpenID)

	// Setup Store
	// Using BoltDB by default
	db, err := bolt.Open(storePath, 0666, nil)
	if err != nil {
		log.Fatalf("Error opening bolt store: %v", err)
	}
	defer db.Close()
	// Invoke a reaper which checks and removes expired sessions periodically.
	defer reaper.Quit(reaper.Run(db, reaper.Options{}))
	store, err := store.New(db, store.Config{}, []byte(secureCookieKeyPair))
	if err != nil {
		log.Fatalf("Error creating session store: %v", err)
	}

	// Session Max-Age in seconds
	sessionMaxAgeSeconds, err := strconv.Atoi(sessionMaxAge)
	if err != nil {
		log.Fatalf("Couldn't convert session MaxAge to int: %v", err)
	}

	s := &server{
		provider: provider,
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     endpoint,
			RedirectURL:  redirectURL.String(),
			Scopes:       oidcScopes,
		},
		// TODO: Add support for Redis
		store:             store,
		whitelist:         whitelist,
		staticDestination: staticDestination,
		userIDOpts: userIDOpts{
			header:      userIDHeader,
			tokenHeader: userIDTokenHeader,
			prefix:      userIDPrefix,
			claim:       userIDClaim,
		},
		sessionMaxAgeSeconds: sessionMaxAgeSeconds,
	}

	// Setup complete, mark server ready
	isReady.Store(true)

	// Register handlers for routes
	router := mux.NewRouter()
	router.HandleFunc("/login/oidc", s.callback).Methods(http.MethodGet)
	router.HandleFunc("/logout", s.logout).Methods(http.MethodGet)
	router.PathPrefix("/").HandlerFunc(s.authenticate)

	// Start server
	log.Infof("Starting web server at %v:%v", hostname, port)
	log.Fatal(http.ListenAndServe(hostname+":"+port, handlers.CORS()(router)))
}
