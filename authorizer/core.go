package authorizer

import (
	"fmt"
	"net/http"

	"github.com/arrikto/oidc-authservice/common"
)

// Authorizer decides if a request, made by the given identity, is allowed.
// The interface draws some inspiration from Kubernetes' interface:
// https://github.com/kubernetes/apiserver/blob/master/pkg/authorization/authorizer/interfaces.go#L67-L72
type Authorizer interface {
	Authorize(r *http.Request, user *common.User) (allowed bool, reason string, err error)
}

const (
	wildcardMatcher = "*"
)

// ruleMatcher is a struct which is used to define matching access based on group
// membership.
type ruleMatcher struct {
	from     string
	allowAny map[string]struct{}
}

func newRuleMatcher(allowlist []string) ruleMatcher {
	m := map[string]struct{}{}
	for _, g := range allowlist {
		m[g] = struct{}{}
	}
	return ruleMatcher{
		from:     fmt.Sprintf("%v", allowlist),
		allowAny: m,
	}
}

// Match matches a user to a set of rules.
//
// It also returns a reason for why the user was allowed access.
func (rm ruleMatcher) Match(user *common.User) (bool, string) {
	if _, ok := rm.allowAny[wildcardMatcher]; ok {
		return ok, "wildcard matching"
	}
	for _, g := range user.Groups {
		if _, ok := rm.allowAny[g]; ok {
			return ok, fmt.Sprintf("in group %s", g)
		}
	}
	return false, fmt.Sprintf("requires membership in one of %v", rm.from)
}
