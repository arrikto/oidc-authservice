package main

import (
	"net/http"
	"strings"

	"github.com/arrikto/oidc-authservice/svc"
	kauthenticator "k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	bearerTokenExpiredMsg = "Token has expired"
)

type kubernetesAuthenticator struct {
	audiences     []string
	authenticator kauthenticator.Request
}

func newKubernetesAuthenticator(c *rest.Config, aud []string) (Authenticator, error) {
	config := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:               false,
		TokenAccessReviewClient: kubernetes.NewForConfigOrDie(c).AuthenticationV1().TokenReviews(),
		APIAudiences:            aud,
	}
	k8sAuthenticator, _, err := config.New()
	return &kubernetesAuthenticator{audiences: aud, authenticator: k8sAuthenticator}, err
}

func (k8sauth *kubernetesAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*User, error) {
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
