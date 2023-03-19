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
		{
			name:       "user groups in allowlist wildcard prefix 1",
			allowlist:  []string{"agroup*"},
			userGroups: []string{"agroup"},
			allowed:    true,
		},
		{
			name:       "user groups in allowlist wildcard prefix 2",
			allowlist:  []string{"agroup*"},
			userGroups: []string{"agroup-any-character"},
			allowed:    true,
		},
		{
			name:       "user groups not in allowlist wildcard prefix 1",
			allowlist:  []string{"agroup*"},
			userGroups: []string{"any-character-agroup-any-character"},
			allowed:    false,
		},
		{
			name:       "user groups not in allowlist wildcard prefix 2",
			allowlist:  []string{"agroup*"},
			userGroups: []string{"any-character-agroup"},
			allowed:    false,
		},
		{
			name:       "user groups in allowlist wildcard suffix 1",
			allowlist:  []string{"*agroup"},
			userGroups: []string{"agroup"},
			allowed:    true,
		},
		{
			name:       "user groups in allowlist wildcard suffix 2",
			allowlist:  []string{"*agroup"},
			userGroups: []string{"any-character-agroup"},
			allowed:    true,
		},
		{
			name:       "user groups not in allowlist wildcard suffix 1",
			allowlist:  []string{"*agroup"},
			userGroups: []string{"agroup-any-character"},
			allowed:    false,
		},
		{
			name:       "user groups not in allowlist wildcard suffix 2",
			allowlist:  []string{"agroup*"},
			userGroups: []string{"any-character-agroup-any-character"},
			allowed:    false,
		},
		{
			name:       "user groups in allowlist wildcard match 1",
			allowlist:  []string{"*agroup*"},
			userGroups: []string{"agroup"},
			allowed:    true,
		},
		{
			name:       "user groups in allowlist wildcard match 2",
			allowlist:  []string{"*agroup*"},
			userGroups: []string{"agroup-any-character"},
			allowed:    true,
		},
		{
			name:       "user groups in allowlist wildcard match 3",
			allowlist:  []string{"*agroup*"},
			userGroups: []string{"any-character-agroup"},
			allowed:    true,
		},
		{
			name:       "user groups in allowlist wildcard match 4",
			allowlist:  []string{"*agroup*"},
			userGroups: []string{"any-character-agroup-any-character"},
			allowed:    true,
		},
		{
			name:       "user groups in allowlist wildcard match 5",
			allowlist:  []string{"group/*/test"},
			userGroups: []string{"group/2/test"},
			allowed:    true,
		},
		{
			name:       "user groups not in allowlist wildcard match 1",
			allowlist:  []string{"group/*/test"},
			userGroups: []string{"group/test"},
			allowed:    false,
		},
		{
			name:       "user groups not in allowlist wildcard match 2",
			allowlist:  []string{"*agroup*"},
			userGroups: []string{"any-character"},
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
