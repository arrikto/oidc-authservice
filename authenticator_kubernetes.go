package main

import (
	"net/http"
	"strings"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	bearerTokenExpiredMsg = "Token has expired"
)

type kubernetesAuthenticator struct {
	audiences     []string
	authenticator authenticator.Request
}

func newKubernetesAuthenticator(c *rest.Config, aud []string) (authenticator.Request, error) {
	config := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:               false,
		TokenAccessReviewClient: kubernetes.NewForConfigOrDie(c).AuthenticationV1().TokenReviews(),
		APIAudiences:            aud,
	}
	k8sAuthenticator, _, err := config.New()
	return &kubernetesAuthenticator{audiences: aud, authenticator: k8sAuthenticator}, err
}

func (k8sauth *kubernetesAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	resp, found, err := k8sauth.authenticator.AuthenticateRequest(
		r.WithContext(authenticator.WithAudiences(r.Context(), k8sauth.audiences)),
	)

	// If the request contains an expired token, we stop trying and return 403
	if err != nil && strings.Contains(err.Error(), bearerTokenExpiredMsg) {
		return nil, false, &loginExpiredError{Err: err}
	}
	return resp, found, err
}
