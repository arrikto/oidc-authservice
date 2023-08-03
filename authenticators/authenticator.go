package authenticators

import (
	"net/http"

	"github.com/arrikto/oidc-authservice/common"
)

type Cacheable interface {
	GetCacheKey(r *http.Request) string
}

type Authenticator interface {
	// Authenticate tries to authenticate a request and
	// returns a User and error if authentication fails.
	Authenticate(w http.ResponseWriter, r *http.Request) (*common.User, bool, error)
}
