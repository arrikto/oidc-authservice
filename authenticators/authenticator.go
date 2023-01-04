package authenticators

import (
	"net/http"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

type AuthenticatorRequest authenticator.Request

type Cacheable interface {
	GetCacheKey(r *http.Request) string
}