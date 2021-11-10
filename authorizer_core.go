package main

import (
	"net/http"

	"github.com/arrikto/oidc-authservice/authenticator"
)

// Authorizer decides if a request, made by the given identity, is allowed.
// The interface draws some inspiration from Kubernetes' interface:
// https://github.com/kubernetes/apiserver/blob/master/pkg/authorization/authorizer/interfaces.go#L67-L72
type Authorizer interface {
	Authorize(r *http.Request, user *authenticator.User) (allowed bool, reason string, err error)
}
