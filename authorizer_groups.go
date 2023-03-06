package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

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
	allowAll  bool
	allowlist []string
}

// wildCardToRegexp converts a wildcard pattern to a regular expression pattern.
func wildCardToRegexp(pattern string) string {
	components := strings.Split(pattern, "*")
	if len(components) == 1 {
		// if len is 1, there are no *'s, return exact match pattern
		return "^" + pattern + "$"
	}
	var result strings.Builder
	for i, literal := range components {

		// Replace * with .*
		if i > 0 {
			result.WriteString(".*")
		}

		// Quote any regular expression meta characters in the
		// literal text.
		result.WriteString(regexp.QuoteMeta(literal))
	}
	return "^" + result.String() + "$"
}

func match(pattern string, value string) bool {
	result, _ := regexp.MatchString(wildCardToRegexp(pattern), value)
	return result
}

func newGroupsAuthorizer(allowlist []string) Authorizer {
	allowAll := false
	for _, g := range allowlist {
		if g == wildcardMatcher {
			allowAll = true
			break
		}
	}
	return &groupsAuthorizer{
		allowAll:  allowAll,
		allowlist: allowlist,
	}
}

func (ga *groupsAuthorizer) Authorize(r *http.Request, userinfo user.Info) (bool, string, error) {
	if ga.allowAll {
		return true, "", nil
	}
	for _, group := range userinfo.GetGroups() {
		for _, allowedGroupPattern := range ga.allowlist {
			if match(allowedGroupPattern, group) {
				return true, "", nil
			}
		}
	}
	reason := fmt.Sprintf("User's groups ([%s]) are not in allowlist.",
		strings.Join(userinfo.GetGroups(), ","))
	return false, reason, nil
}
