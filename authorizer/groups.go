package authorizer

import (
	"net/http"

	"github.com/arrikto/oidc-authservice/authenticator"
)

type groupsAuthorizer struct {
	m ruleMatcher
}

func NewGroupsAuthorizer(allowlist []string) Authorizer {
	return &groupsAuthorizer{
		m: newRuleMatcher(allowlist),
	}
}

func (ga *groupsAuthorizer) Authorize(r *http.Request, user *authenticator.User) (bool, string, error) {
	authed, reason := ga.m.Match(user)
	return authed, reason, nil
}
