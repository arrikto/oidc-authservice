package main

import (
	"fmt"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/user"
	"net/http"
	"net/url"
	"testing"
)

const (
	mockAuthUrl = "https://test/auth"
	// Issuer: "Issuer", Username: "Test", "Role: Test"
	JWT = "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiVGVzdCIsIklzc3VlciI6Iklzc3VlciIsIlVzZXJuYW1lIjoiVGVzdCIsImV4cCI6MTY2NzM4MzY0MiwiaWF0IjoxNjY3MzgzNjQyfQ.D75w4zDiQfTwDtrFCz0m9qlBalLhoEhxWqw83unoFCk\n"
	/* The decoded JWT token has the following content:
	   Header:
	   {
             "alg": "HS256"
           }
	   Payload:
	   {
             "Role": "Test",
             "Issuer": "Issuer",
             "Username": "Test",
             "exp": 1667383642,
             "iat": 1667383642
           }
	*/
)


func createRequest(addJWT bool) *http.Request {
	var currentUrl url.URL
	currentUrl.Path = "/test"
	var headers = http.Header{}
	if addJWT {
		headers.Add("Authorization", fmt.Sprintf("Bearer: %s", JWT))
	}
	return &http.Request{
		Method: "GET",
		URL:    &currentUrl,
		Host:   "host:80",
		Header: headers,
	}
}

func TestExternalAuthorizer_Authorize(t *testing.T) {

	type args struct {
		r        *http.Request
		userinfo user.Info
	}
	type httpMock struct {
		url    string
		method string
		status int
		body   string
	}
	type checks func(t *testing.T)
	tests := []struct {
		name          string
		args          args
		httpMock      httpMock
		checks        checks
		expectAllowed bool
		expectReason  string
		expectErr     bool
	}{
		{
			name: "user is allowed",
			args: args{
				r:        createRequest(true),
				userinfo: &user.DefaultInfo{Name: "Test"},
			},
			httpMock: httpMock{
				url: mockAuthUrl,
				method: "POST",
				status: 200,
				body:   "User Allowed",
			},
			checks: func(t *testing.T) {
				// Verify that a call has been made in the backend.
				calls := httpmock.GetCallCountInfo()[fmt.Sprintf("POST %v",mockAuthUrl)]
				require.Equal(t, 1, calls)
			},
			expectAllowed: true,
			expectReason:  "",
			expectErr:     false,
		},
		{
			name: "user is unauthorized",
			args: args{
				r:        createRequest(true),
				userinfo: &user.DefaultInfo{Name: "Test"},
			},
			httpMock: httpMock{
				url: mockAuthUrl,
				method: "POST",
				status: 401,
				body:   "User Unauthorized",
			},
			checks: func(t *testing.T) {
				// Verify that a call has been made in the backend.
				calls := httpmock.GetCallCountInfo()[fmt.Sprintf("POST %v",mockAuthUrl)]
				require.Equal(t, 1, calls)
			},
			expectAllowed: false,
			expectReason:  "User Unauthorized",
			expectErr:     false,
		},
		{
			name: "authorization server exception",
			args: args{
				r:        createRequest(true),
				userinfo: &user.DefaultInfo{Name: "Test"},
			},
			httpMock: httpMock{
				url: mockAuthUrl,
				method: "POST",
				status: 500,
				body:   "Internal server error",
			},
			checks: func(t *testing.T) {
				// Verify that a call has been made in the backend.
				calls := httpmock.GetCallCountInfo()[fmt.Sprintf("POST %v",mockAuthUrl)]
				require.Equal(t, 1, calls)
			},
			expectAllowed: false,
			expectReason:  "",
			expectErr:     true,
		},
		{
			name: "connection error",
			args: args{
				r:        createRequest(true),
				userinfo: &user.DefaultInfo{Name: "Test"},
			},
			httpMock: httpMock{
				url: "http://wrongurl/auth",
				method: "POST",
				status: 500,
				body:   "Internal server error",
			},
			checks: func(t *testing.T) {
				// Verify that a call has not been made in the backend.
				calls := httpmock.GetCallCountInfo()[fmt.Sprintf("POST %v",mockAuthUrl)]
				require.Equal(t, 0, calls)
			},
			expectAllowed: false,
			expectReason:  "Error while authorizing the request",
			expectErr:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := ExternalAuthorizer{
				url: mockAuthUrl,
			}
			// Mock HTTP.
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()
			httpmock.RegisterResponder(test.httpMock.method, test.httpMock.url,
				httpmock.NewStringResponder(test.httpMock.status, test.httpMock.body))
			// Call the method.
			gotAllowed, gotReason, err := e.Authorize(test.args.r, test.args.userinfo)
			// Verify
			if test.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.expectAllowed, gotAllowed, "Authorize() gotAllowed = %v, expect %v", gotAllowed, test.expectAllowed)
			require.Equal(t, test.expectReason, gotReason, "Authorize() gotReason = %v, expect %v", gotReason, test.expectReason)

			if test.checks != nil {
				test.checks(t)
			}
		})
	}
}

func TestExternalAuthorizer_getRequestInfo(t *testing.T) {
	e := ExternalAuthorizer{
		url: mockAuthUrl,
	}

	request := createRequest(true)

	r := e.getRequestInfo(request)
	require.Equal(t, AuthorizationRequestInfo{"host", 80, "/test", "GET"}, r)
}

func TestExternalAuthorizer_getUserInfo(t *testing.T) {
	type fields struct {
		url string
	}
	type args struct {
		r        *http.Request
		userinfo user.Info
	}
	nonJWTAuthorization := createRequest(false)
	nonJWTAuthorization.Header.Add("Authorization", "Bearer: Test")
	tests := []struct {
		name     string
		fields   fields
		args     args
		expectInfo AuthorizationUserInfo
	}{
		{
			name:   "parse user info without JWT",
			fields: fields{mockAuthUrl},
			args: args{
				r: createRequest(false),
				userinfo: &user.DefaultInfo{
					Name:   "Test",
					UID:    "1",
					Groups: []string{"test"},
					Extra:  map[string][]string{"test": {"test"}},
				},
			},
			expectInfo: AuthorizationUserInfo{
				Name:   "Test",
				Id:     "1",
				Groups: []string{"test"},
				Extra:  map[string][]string{"test": {"test"}},
				Claims: nil,
			},
		},
		{
			name:   "parse user info with JWT",
			fields: fields{mockAuthUrl},
			args: args{
				r: createRequest(true),
				userinfo: &user.DefaultInfo{
					Name:   "Test",
					UID:    "1",
					Groups: []string{"test"},
					Extra:  map[string][]string{"test": {"test"}},
				},
			},
			expectInfo: AuthorizationUserInfo{
				Name:   "Test",
				Id:     "1",
				Groups: []string{"test"},
				Extra:  map[string][]string{"test": {"test"}},
				Claims: map[string]interface{}{
					"Issuer":   "Issuer",
					"Role":     "Test",
					"Username": "Test",
					"exp":      1.667383642e+09,
					"iat":      1.667383642e+09,
				},
			},
		},
		{
			name:   "parse user info with non JWT bearer token",
			fields: fields{mockAuthUrl},
			args: args{
				r: nonJWTAuthorization,
				userinfo: &user.DefaultInfo{
					Name:   "Test",
					UID:    "1",
					Groups: []string{"test"},
					Extra:  map[string][]string{"test": {"test"}},
				},
			},
			expectInfo: AuthorizationUserInfo{
				Name:   "Test",
				Id:     "1",
				Groups: []string{"test"},
				Extra:  map[string][]string{"test": {"test"}},
				Claims: nil,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := ExternalAuthorizer{
				url: test.fields.url,
			}
			gotInfo := e.getUserInfo(test.args.r, test.args.userinfo)
			require.Equal(t, gotInfo, test.expectInfo, "getUserInfo() gotInfo = %v, expect %v",
				gotInfo, test.expectInfo)
		})
	}
}
