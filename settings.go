package main

import (
	"net/url"
	"os"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

type config struct {
	// OIDC Provider
	ProviderURL *url.URL `required:"true" split_words:"true" envconfig:"OIDC_PROVIDER"`

	// OIDC Client
	ClientID                string   `required:"true" split_words:"true"`
	ClientSecret            string   `required:"true" split_words:"true"`
	OIDCAuthURL             *url.URL `split_words:"true"`
	RedirectURL             *url.URL `split_words:"true"`
	OIDCScopes              []string `split_words:"true" default:"openid,email"`
	StrictSessionValidation bool     `split_words:"true"`

	// General
	AuthserviceURLPrefix *url.URL `required:"true" split_words:"true"`
	SkipAuthURLs         []string `split_words:"true" envconfig:"SKIP_AUTH_URLS"`
	AuthHeader           string   `split_words:"true" default:"Authorization"`
	Audiences            []string `default:"istio-ingressgateway.istio-system.svc.cluster.local"`
	HomepageURL          *url.URL `split_words:"true"`
	AfterLoginURL        *url.URL `split_words:"true"`
	AfterLogoutURL       *url.URL `split_words:"true"`

	// Identity Headers
	UserIDHeader string `split_words:"true" default:"kubeflow-userid" envconfig:"USERID_HEADER"`
	GroupsHeader string `split_words:"true" default:"kubeflow-groups"`
	UserIDPrefix string `split_words:"true" envconfig:"USERID_PREFIX"`

	// IDToken
	UserIDClaim       string `split_words:"true" default:"email" envconfig:"USERID_CLAIM"`
	UserIDTokenHeader string `split_words:"true" envconfig:"USERID_TOKEN_HEADER"`
	GroupsClaim       string `split_words:"true" default:"groups"`

	// Infra
	Hostname           string `split_words:"true" envconfig:"SERVER_HOSTNAME"`
	Port               int    `split_words:"true" default:"8080" envconfig:"SERVER_PORT"`
	WebServerPort      int    `split_words:"true" default:"8082"`
	ReadinessProbePort int    `split_words:"true" default:"8081"`
	CABundlePath       string `split_words:"true" envconfig:"CA_BUNDLE"`
	SessionStorePath   string `split_words:"true" default:"/var/lib/authservice/data.db"`
	SessionMaxAge      int    `split_words:"true" default:"86400"`

	// Site
	ClientName          string            `split_words:"true" default:"AuthService"`
	ThemesURL           *url.URL          `split_words:"true" default:"themes"`
	Theme               string            `split_words:"true" default:"kubeflow"`
	TemplatePath        []string          `split_words:"true"`
	UserTemplateContext map[string]string `ignored:"true"`

	// Authorization
	GroupsAllowlist []string `split_words:"true" default:"*"`
}

func parseConfig() (*config, error) {

	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		return nil, err
	}

	if len(c.RedirectURL.String()) == 0 {
		c.RedirectURL = resolvePathReference(c.AuthserviceURLPrefix, OIDCCallbackPath)
	}
	if len(c.HomepageURL.String()) == 0 {
		c.HomepageURL = resolvePathReference(c.AuthserviceURLPrefix, HomepagePath)
	}
	if len(c.AfterLogoutURL.String()) == 0 {
		c.AfterLogoutURL = resolvePathReference(c.AuthserviceURLPrefix, AfterLogoutPath)
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
