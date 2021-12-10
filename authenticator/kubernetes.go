package authenticator

import (
	"net/http"
	"strings"

	"github.com/arrikto/oidc-authservice/logger"
	"github.com/arrikto/oidc-authservice/svc"
	kauthenticator "k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	bearerTokenExpiredMsg = "Token has expired"
)

type kubernetesAuthenticator struct {
	audiences     []string
	authenticator kauthenticator.Request
}

func NewKubernetesAuthenticator(aud []string) (Authenticator, error) {
	restConfig, err := config.GetConfig()
	if err != nil {
		return nil, err
	}

	authConfig := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous: false,
		TokenAccessReviewClient: kubernetes.NewForConfigOrDie(
			restConfig).AuthenticationV1().TokenReviews(),
		APIAudiences: aud,
	}
	k8sAuthenticator, _, err := authConfig.New()
	return &kubernetesAuthenticator{audiences: aud, authenticator: k8sAuthenticator}, err
}

func (k8sauth *kubernetesAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*User, error) {
	logger := logger.ForRequest(r)
	logger.Info("Attempting k8s authentication")

	resp, found, err := k8sauth.authenticator.AuthenticateRequest(
		r.WithContext(kauthenticator.WithAudiences(r.Context(), k8sauth.audiences)),
	)
	// If the request contains an expired token, we stop trying and return 403
	if err != nil && strings.Contains(err.Error(), bearerTokenExpiredMsg) {
		return nil, &svc.LoginExpiredError{Err: err}
	}

	if !found {
		return nil, nil
	}

	return &User{Name: resp.User.GetName(), Groups: resp.User.GetGroups()}, err
}
