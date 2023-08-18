package common

import (
	"net/url"
	"os"
	"strings"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	// OIDC Provider
	ProviderURL *url.URL `required:"true" split_words:"true" envconfig:"OIDC_PROVIDER"`

	// OIDC Client
	ClientID                string   `required:"true" split_words:"true"`
	ClientSecret            string   `required:"true" split_words:"true"`
	OIDCAuthURL             *url.URL `split_words:"true"`
	RedirectURL             *url.URL `split_words:"true"`
	OIDCScopes              []string `split_words:"true" default:"openid,email"`
	StrictSessionValidation bool     `split_words:"true"`
	OIDCStateStorePath      string   `split_words:"true" default:"/var/lib/authservice/data.db"`

	// General
	AuthserviceURLPrefix *url.URL `required:"true" split_words:"true"`
	SkipAuthURLs         []string `split_words:"true" envconfig:"SKIP_AUTH_URLS"`
	AuthHeader           string   `split_words:"true" default:"Authorization"`
	AuthMethodHeader     string   `split_words:"true" default:"Auth-Method"`
	SchemeDefault        string   `split_words:"true" default:"https"`
	SchemeHeader         string   `split_words:"true" default:"X-Forwarded-Proto"`
	Audiences            []string `default:"istio-ingressgateway.istio-system.svc.cluster.local"`
	HomepageURL          *url.URL `split_words:"true"`
	AfterLoginURL        *url.URL `split_words:"true"`
	AfterLogoutURL       *url.URL `split_words:"true"`
	VerifyAuthURL        *url.URL `split_words:"true"`
	LogLevel             string   `split_words:"true" default:"INFO"`

	// Identity Headers
	UserIDHeader      string            `split_words:"true" envconfig:"USERID_HEADER"`
	GroupsHeader      string            `split_words:"true"`
	UserIDPrefix      string            `split_words:"true" envconfig:"USERID_PREFIX"`
	UserIDTransformer UserIDTransformer `envconfig:"USERID_TRANSFORMERS"`
	TokenHeader       string            `split_words:"true" default:"Authorization"`
	TokenScheme       string            `split_words:"true" default:"Bearer"`

	// IDToken
	UserIDClaim       string `split_words:"true" default:"email" envconfig:"USERID_CLAIM"`
	UserIDTokenHeader string `split_words:"true" envconfig:"USERID_TOKEN_HEADER"`
	GroupsClaim       string `split_words:"true" default:"groups"`
	IDTokenHeader     string `split_words:"true" default:"Authorization" envconfig:"ID_TOKEN_HEADER"`

	// Infra
	Hostname              string `split_words:"true" envconfig:"SERVER_HOSTNAME"`
	Port                  int    `split_words:"true" default:"8080" envconfig:"SERVER_PORT"`
	WebServerPort         int    `split_words:"true" default:"8082"`
	ReadinessProbePort    int    `split_words:"true" default:"8081"`
	CABundlePath          string `split_words:"true" envconfig:"CA_BUNDLE"`
	SessionStoreType      string `split_words:"true" default:"boltdb"`
	SessionStorePath      string `split_words:"true" default:"/var/lib/authservice/data.db"`
	SessionStoreRedisAddr string `split_words:"true" default:"127.0.0.1:6379"`
	SessionStoreRedisPWD  string `split_words:"true" default:"" envconfig:"SESSION_STORE_REDIS_PWD"`
	SessionStoreRedisDB   int    `split_words:"true" default:"0" envconfig:"SESSION_STORE_REDIS_DB"`
	SessionMaxAge         int    `split_words:"true" default:"86400"`
	SessionSameSite       string `split_words:"true" default:"Lax"`
	SessionDomain         string `split_words:"true"`

	// Site
	ClientName          string            `split_words:"true" default:"AuthService"`
	ThemesURL           *url.URL          `split_words:"true" default:"themes"`
	Theme               string            `split_words:"true" default:"kubeflow"`
	TemplatePath        []string          `split_words:"true"`
	UserTemplateContext map[string]string `ignored:"true"`

	// bearerUserInfoCache configuration
	CacheEnabled           bool `split_words:"true" default:"false" envconfig:"CACHE_ENABLED"`
	CacheExpirationMinutes int  `split_words:"true" default:"5" envconfig:"CACHE_EXPIRATION_MINUTES"`

	// Authenticators configurations
	IDTokenAuthnEnabled     bool   `split_words:"true" default:"true" envconfig:"IDTOKEN_AUTHN_ENABLED"`
	KubernetesAuthnEnabled  bool   `split_words:"true" default:"true" envconfig:"KUBERNETES_AUTHN_ENABLED"`
	AccessTokenAuthnEnabled bool   `split_words:"true" default:"true" envconfig:"ACCESS_TOKEN_AUTHN_ENABLED"`
	AccessTokenAuthn        string `split_words:"true" default:"jwt" envconfig:"ACCESS_TOKEN_AUTHN"`

	// Authorization
	GroupsAllowlist  []string `split_words:"true" default:"*"`
	ExternalAuthzUrl string   `split_words:"true" default:""`
	AuthzConfigPath  string   `split_words:"true"`
}

func ParseConfig() (*Config, error) {

	var c Config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	if len(c.RedirectURL.String()) == 0 {
		c.RedirectURL = ResolvePathReference(c.AuthserviceURLPrefix, OIDCCallbackPath)
	}
	if len(c.HomepageURL.String()) == 0 {
		c.HomepageURL = ResolvePathReference(c.AuthserviceURLPrefix, HomepagePath)
	}
	if len(c.AfterLogoutURL.String()) == 0 {
		c.AfterLogoutURL = ResolvePathReference(c.AuthserviceURLPrefix, AfterLogoutPath)
	}
	if len(c.VerifyAuthURL.String()) == 0 {
		c.VerifyAuthURL = ResolvePathReference(c.AuthserviceURLPrefix, VerifyEndpoint)
	}
	if !validAccessTokenAuthn(c.AccessTokenAuthnEnabled, c.AccessTokenAuthn){
		log.Fatalf("Unsupported access token authentication configuration:" +
			"ACCESS_TOKEN_AUTHN=%s",c.AccessTokenAuthn)
	}
	if !validSessionStoreType(c.SessionStoreType){
		log.Fatalf("Unsupported value for the type of the session store:" +
			"SESSION_STORE_TYPE=%s",c.SessionStoreType)
	}
	if !validLogLevel(c.LogLevel){
		log.Fatalf("Unsupported value for the log level messages:" +
		"LOG_LEVEL=%s",c.LogLevel)
	}
	c.UserTemplateContext = getEnvsFromPrefix("TEMPLATE_CONTEXT_")

	c.SkipAuthURLs = trimSpaceFromStringSliceElements(c.SkipAuthURLs)
	c.SkipAuthURLs = ensureInSlice(c.AuthserviceURLPrefix.Path, c.SkipAuthURLs)

	c.OIDCScopes = trimSpaceFromStringSliceElements(c.OIDCScopes)
	c.OIDCScopes = ensureInSlice("openid", c.OIDCScopes)

	c.TemplatePath = trimSpaceFromStringSliceElements(c.TemplatePath)
	c.TemplatePath = ensureInSlice("web/templates/default", c.TemplatePath)

	return &c, err
}

func getEnvsFromPrefix(prefix string) map[string]string {
	res := map[string]string{}
	for _, env := range os.Environ() {
		parts := strings.Split(env, "=")
		key, value := parts[0], parts[1]
		if strings.HasPrefix(key, prefix) {
			res[strings.TrimPrefix(key, prefix)] = value
		}
	}
	return res
}

func trimSpaceFromStringSliceElements(slice []string) []string {
	ret := []string{}
	for _, elem := range slice {
		elem = strings.TrimSpace(elem)
		if len(elem) > 0 {
			ret = append(ret, elem)
		}
	}
	return ret
}

func ensureInSlice(elem string, slice []string) []string {
	for _, s := range slice {
		if elem == s {
			return slice
		}
	}
	slice = append([]string{elem}, slice...)
	return slice
}

// validAccessTokenAuthn() examines if the admins have configured
// a valid value for the ACCESS_TOKEN_AUTHN envvar.
func validAccessTokenAuthn(AccessTokenAuthnEnabledEnv bool, AccessTokenAuthnEnv string) (bool){
	if !AccessTokenAuthnEnabledEnv {
		return true
	}
	if AccessTokenAuthnEnv == "jwt" {
		return true
	}
	if AccessTokenAuthnEnv == "opaque"{
		return true
	}

	log.Warn("Please select exactly one of the supported options: " +
	"i) jwt: to enable the JWT access token authentication method, " +
	"ii) opaque: to enable the opaque access token authentication method")

	return false
}

// validSessionStoreType() examines if the admins have configured a valid value
// for the SESSION_STORE_TYPE envvar.
func validSessionStoreType(SessionStoreType string) (bool){
	if SessionStoreType == "boltdb" {
		return true
	}
	if SessionStoreType == "redis"{
		return true
	}
	if SessionStoreType == "redisfailover"{
		return true
	}

	log.Warn("Please select exactly one of the options: " +
	"i) boltdb: to select the BoltDB supported session store, " +
	"ii) redis: to select the Redis supported session store, " +
	"iiI) redisfailver: to select the RedisFailover supported session store")

	return false
}

// validLogLevel() examines if the admins have configured a valid value for the
// LOG_LEVEL envvar.
func validLogLevel(level string) bool {
	if level == "FATAL" {
		return true
	} else if level == "ERROR" {
		return true
	} else if level == "WARN" {
		return true
	} else if level == "INFO" {
		return true
	} else if level == "DEBUG" {
		return true
	}

	log.Warn("Please select exactly one of the options for the LOG_LEVEL: " +
	"i) FATAL: to print fatal log level messages, " +
	"ii) ERROR: to print error log level messages and above, " +
	"iii) WARN: to print warn log level messages and above, " +
	"iv) INFO: to print info log level messages and above, " +
	"v) DEBUG: to pring messages of all the available log levels")

	return false
}
