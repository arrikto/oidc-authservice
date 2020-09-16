package main

import (
	"fmt"
	"net/http"

	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	wildcardMatcher = "*"
)

// Authorizer decides if a request, made by the given identity, is allowed.
// The interface draws some inspiration from Kubernetes' interface:
// https://github.com/kubernetes/apiserver/blob/master/pkg/authorization/authorizer/interfaces.go#L67-L72
type Authorizer interface {
	Authorize(r *http.Request, userinfo user.Info) (allowed bool, reason string, err error)
}

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

func (ga *groupsAuthorizer) Authorize(r *http.Request, userinfo user.Info) (bool, string, error) {
	if ga.allowed[wildcardMatcher] {
		return true, "", nil
	}
	for _, g := range userinfo.GetGroups() {
		if ga.allowed[g] {
			return true, "", nil
		}
	}
	reason := fmt.Sprintf("User's groups ('%v') are not in allowlist.", userinfo.GetGroups())
	return false, reason, nil
}
