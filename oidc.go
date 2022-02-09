package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// UserInfo represents the OpenID Connect userinfo claims.
type UserInfo struct {
	Subject       string `json:"sub"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`

	RawClaims []byte
}

// Claims unmarshals the raw JSON object claims into the provided object.
func (u *UserInfo) Claims(v interface{}) error {
	if u.RawClaims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(u.RawClaims, v)
}

// GetUserInfo uses the token source to query the provider's user info endpoint.
// We reimplement UserInfo [1] instead of using the go-oidc's library UserInfo, in
// order to include HTTP response information in case of an error during
// contacting the UserInfo endpoint.
//
// [1]: https://github.com/coreos/go-oidc/blob/v2.1.0/oidc.go#L180
func GetUserInfo(ctx context.Context, provider *oidc.Provider, tokenSource oauth2.TokenSource) (*UserInfo, error) {

	discoveryClaims := &struct {
		UserInfoURL string `json:"userinfo_endpoint"`
	}{}
	if err := provider.Claims(discoveryClaims); err != nil {
		return nil, errors.Errorf("Error unmarshalling OIDC discovery document claims: %v", err)
	}

	userInfoURL := discoveryClaims.UserInfoURL
	if userInfoURL == "" {
		return nil, errors.New("oidc: user info endpoint is not supported by this provider")
	}

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, errors.Errorf("oidc: create GET request: %v", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		return nil, errors.Errorf("oidc: get access token: %v", err)
	}
	token.SetAuthHeader(req)

	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &requestError{
			Response: resp,
			Body:     body,
			Err:      errors.Errorf("oidc: Calling UserInfo endpoint failed. body: %s", body),
		}
	}

        raw := struct {
		Subject       string      `json:"sub"`
		Profile       string      `json:"profile"`
		Email         string      `json:"email"`
		EmailVerified interface{} `json:"email_verified"`

		RawClaims []byte
        }{}

        err = json.Unmarshal(body,&raw)
        if err != nil {
                return nil, errors.Errorf("oidc: fail to decode userinfo: %v", err)
        }

        userInfo := &UserInfo{
		Subject: raw.Subject,
		Profile: raw.Profile,
		Email: raw.Email,
	}

	switch ParsedEmailVerified := raw.EmailVerified.(type) {
	case bool:
		userInfo.EmailVerified = ParsedEmailVerified
	case nil:
		userInfo.EmailVerified = false
	case string:
		boolValue, err := strconv.ParseBool(ParsedEmailVerified)
		if err != nil {
			return nil, errors.Errorf("oidc: failed to decode the email_verified field of userinfo: %v", err)
		}
		userInfo.EmailVerified = boolValue
	default:
		return nil, errors.Errorf("oidc: unsupported type for the email_verified field")
	}

	userInfo.RawClaims = body
	return userInfo, nil
}
