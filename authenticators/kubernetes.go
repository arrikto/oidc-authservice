package authenticators

import (
	"net/http"
	"strings"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"github.com/arrikto/oidc-authservice/common"
)

const (
	bearerTokenExpiredMsg = "Token has expired"
)

type KubernetesAuthenticator struct {
	Audiences     []string
	Authenticator AuthenticatorRequest
}

func NewKubernetesAuthenticator(c *rest.Config, aud []string) (AuthenticatorRequest, error) {
	config := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:                false,
		TokenAccessReviewClient:  kubernetes.NewForConfigOrDie(c).AuthenticationV1(),
		WebhookRetryBackoff:      webhook.DefaultRetryBackoff(),
		APIAudiences:             aud,
	}
	k8sAuthenticator, _, err := config.New()
	return &KubernetesAuthenticator{Audiences: aud, Authenticator: k8sAuthenticator}, err
}

func (k8sauth *KubernetesAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	resp, found, err := k8sauth.Authenticator.AuthenticateRequest(
		r.WithContext(authenticator.WithAudiences(r.Context(), k8sauth.Audiences)),
	)

	// If the request contains an expired token, we stop trying and return 403
	if err != nil && strings.Contains(err.Error(), bearerTokenExpiredMsg) {
		return nil, false, &common.LoginExpiredError{Err: err}
	}

	if found {
		// Authentication using header successfully completed
		extra := map[string][]string{"auth-method": {"header"}}

		resp = &authenticator.Response{
			Audiences: resp.Audiences,
			User: &user.DefaultInfo{
				Name:   resp.User.GetName(),
				UID:    resp.User.GetUID(),
				Groups: resp.User.GetGroups(),
				Extra:  extra,
			},
		}
	}

	return resp, found, err
}

// The Kubernetes Authenticator implements the Cacheable
// interface with the getCacheKey().
func (k8sauth *KubernetesAuthenticator) GetCacheKey(r *http.Request) (string) {
	return common.GetBearerToken(r.Header.Get("Authorization"))

}
