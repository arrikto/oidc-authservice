package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/arrikto/oidc-authservice/authenticator"
)

const (
	wildcardMatcher = "*"
)

type groupsAuthorizer struct {
	allowed map[string]bool
}

func newGroupsAuthorizer(allowlist []string) Authorizer {
	allowed := map[string]bool{}
	for _, g := range allowlist {
		if g == wildcardMatcher {
			allowed = map[string]bool{g: true}
			break
		}
		allowed[g] = true
	}
	return &groupsAuthorizer{
		allowed: allowed,
	}
}

func (ga *groupsAuthorizer) Authorize(r *http.Request, user *authenticator.User) (bool, string, error) {
	if ga.allowed[wildcardMatcher] {
		return true, "", nil
	}
	for _, g := range user.Groups {
		if ga.allowed[g] {
			return true, "", nil
		}
	}
	reason := fmt.Sprintf("User's groups ([%s]) are not in allowlist.",
		strings.Join(user.Groups, ","))
	return false, reason, nil
}
