package authorizer

import (
	"net/http"

	"github.com/arrikto/oidc-authservice/common"
)

type groupsAuthorizer struct {
	m ruleMatcher
}

func NewGroupsAuthorizer(allowlist []string) Authorizer {
	return &groupsAuthorizer{
		m: newRuleMatcher(allowlist),
	}
}

func (ga *groupsAuthorizer) Authorize(r *http.Request, user *common.User) (bool, string, error) {
	authed, reason := ga.m.Match(user)
	return authed, reason, nil
}
