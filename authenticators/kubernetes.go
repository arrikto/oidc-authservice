package authenticators

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/arrikto/oidc-authservice/common"
	kauthenticator "k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	bearerTokenExpiredMsg = "Token has expired"
)

type KubernetesAuthenticator struct {
	Audiences     []string
	Authenticator kauthenticator.Request
}

func NewKubernetesAuthenticator(aud []string) (Authenticator, error) {
	restConfig, err := config.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("Error getting K8s config: %v", err)
	}

	authConfig := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:               false,
		TokenAccessReviewClient: kubernetes.NewForConfigOrDie(restConfig).AuthenticationV1(),
		WebhookRetryBackoff:     webhook.DefaultRetryBackoff(),
		APIAudiences:            aud,
	}
	k8sAuthenticator, _, err := authConfig.New()
	if err != nil {
		return nil, fmt.Errorf("Error creating K8s authenticator: %v", err)
	}

	return &KubernetesAuthenticator{Audiences: aud, Authenticator: k8sAuthenticator}, nil
}

func (k8sauth *KubernetesAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*common.User, bool, error) {
	logger := common.RequestLogger(r, "kubernetes authenticator")
	logger.Info("Attempting k8s authentication")

	resp, found, err := k8sauth.Authenticator.AuthenticateRequest(
		r.WithContext(kauthenticator.WithAudiences(r.Context(), k8sauth.Audiences)),
	)

	// If the request contains an expired token, we stop trying and return 403
	if err != nil && strings.Contains(err.Error(), bearerTokenExpiredMsg) {
		return nil, false, &common.LoginExpiredError{Err: err}
	}

	if !found {
		return nil, false, nil
	}

	// Authentication using header successfully completed
	extra := map[string][]string{"auth-method": {"header"}}

	return &common.User{
		Name:   resp.User.GetName(),
		UID:    resp.User.GetUID(),
		Groups: resp.User.GetGroups(),
		Extra:  extra,
	}, true, err
}

// The Kubernetes Authenticator implements the Cacheable
// interface with the getCacheKey().
func (k8sauth *KubernetesAuthenticator) GetCacheKey(r *http.Request) string {
	return common.GetBearerToken(r.Header.Get("Authorization"))

}
