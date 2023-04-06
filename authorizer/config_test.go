package authorizer

import (
	"net/http"
	"testing"

	"github.com/arrikto/oidc-authservice/authenticator"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	input := []byte(`rules:
  foo.bar.io:
    groups:
      - baz@bar.com
      - beef@bar.com
  theo.von.io:
    groups:
      - ratking@von.io
      - plug@von.io`)

	ca := &configAuthorizer{}
	authzConfig, err := ca.parse(input)
	if err != nil {
		t.Errorf("error parsing config: %v", err)
	}
	t.Logf("loaded config: %v", *authzConfig)
}

func user(n string, groups ...string) *authenticator.User {
	return &authenticator.User{Name: n, Groups: groups}
}

func TestConfigAuthorizerMatching(t *testing.T) {
	type matchTCase struct {
		host  string
		match bool
		user  *authenticator.User
	}

	tests := []struct {
		in       string
		behavior []matchTCase
	}{
		{
			in: "./testdata/authz.yaml",
			behavior: []matchTCase{
				// foo.bar.io tests
				{"foo.bar.io", false, user("none")},
				{"foo.bar.io", false, user("wrong", "wrong")},
				{"foo.bar.io", false, user("match1", "a@b.go")},
				{"foo.bar.io", false, user("match2", "ok@ok.go", "b@b.go")},
				// bar.io tests
				{"foo.bar.io", false, user("matching foo", "a@b.go")},
				{"foo.bar.io", false, user("match", "c@c.go")},
				// default unknown host behavior
				{"unknown host", true, user("no groups")},
			},
		},
		{
			in: "./testdata/allowAll.yaml",
			behavior: []matchTCase{
				{"happytohaveyou.io", true, user("no groups")},
				{"nothappy.io", false, user("no groups")},
				{"unknown host", true, user("no groups")},
			},
		},
		{
			in: "./testdata/allowNoneDefault.yaml",
			behavior: []matchTCase{
				{"unknown host", false, user("no groups")},
				{"nothappy.io", false, user("no groups")},
				{"ok.io", true, user("matches", "foo@bar.go")},
			},
		},
		{
			in: "./testdata/allowSingleGroupDefault.yaml",
			behavior: []matchTCase{
				{"unknown host", false, user("no groups")},
				{"unknown host", true, user("default match", "foo")},
				// doesn't match other matcher
				{"foo.bar.io", false, user("default doesnt match", "foo")},
				{"foo.bar.io", false, user("match", "baz@bar.go")},
			},
		},
	}

	for _, tcase := range tests {
		t.Run(tcase.in, func(t *testing.T) {
			ca, err := NewConfigAuthorizer(tcase.in)
			if err != nil {
				t.Fatal(err)
			}
			// t.Logf("created ca %+v", ca)
			for _, tc := range tcase.behavior {
				authed, reason, err := ca.Authorize(&http.Request{Host: tc.host}, tc.user)
				require.NoError(t, err, "unexpected error")
				require.Equalf(t, tc.match, authed, "%s", reason)
			}
		})
	}
}
