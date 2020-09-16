package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestGroupsAuthorizer(t *testing.T) {
	tests := []struct {
		name       string
		allowlist  []string
		userGroups []string
		allowed    bool
	}{
		{
			name:       "allow all",
			allowlist:  []string{wildcardMatcher},
			userGroups: []string{},
			allowed:    true,
		},
		{
			name:       "deny all",
			allowlist:  []string{},
			userGroups: []string{"a"},
			allowed:    false,
		},
		{
			name:       "user group in allowlist",
			allowlist:  []string{"a", "b", "c"},
			userGroups: []string{"c", "d"},
			allowed:    true,
		},
		{
			name:       "user groups not in allowlist",
			allowlist:  []string{"a", "b", "c"},
			userGroups: []string{"d", "e"},
			allowed:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authz := newGroupsAuthorizer(test.allowlist)
			userInfo := &user.DefaultInfo{
				Groups: test.userGroups,
			}
			allowed, reason, err := authz.Authorize(nil, userInfo)
			require.NoError(t, err, "Unexpected error")
			require.Equalf(t, test.allowed, allowed, "Reason: %s", reason)
		})
	}
}
