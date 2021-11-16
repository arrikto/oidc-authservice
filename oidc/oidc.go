package oidc

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/arrikto/oidc-authservice/svc"
	"github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type IdProvider interface {
	Claims(v interface{}) error
	Endpoint() oauth2.Endpoint
	Verifier(config *oidc.Config) *oidc.IDTokenVerifier
}

func NewOidcConfig(clientID string) *oidc.Config {
	return &oidc.Config{ClientID: clientID}
}

func NewOidcProvider(ctx context.Context, u *url.URL) IdProvider {
	var provider IdProvider

	for {
		provider, err := oidc.NewProvider(ctx, u.String())
		if err == nil {
			return provider
		}
		log.Errorf("OIDC provider setup failed, retrying in 10 seconds: %v", err)
		time.Sleep(10 * time.Second)
	}

	return provider
}

type Claims struct {
	rawClaims   map[string]interface{}
	userIDClaim string
	groupsClaim string
}

type ClaimProvider interface {
	Claims(v interface{}) error
}

func NewClaims(cp ClaimProvider, userIDClaim, groupsClaim string) (Claims, error) {
	c := Claims{
		rawClaims:   map[string]interface{}{},
		userIDClaim: userIDClaim,
		groupsClaim: groupsClaim,
	}
	err := cp.Claims(&c.rawClaims)
	return c, err
}

func (c *Claims) UserID() (string, error) {
	claim := c.rawClaims[c.userIDClaim]
	if claim == nil {
		return "", errors.New("Couldn't find userID claim")
	}
	return claim.(string), nil
}

func (c *Claims) Groups() []string {
	gc := c.rawClaims[c.groupsClaim]
	if gc == nil {
		return []string{}
	}

	in := gc.([]interface{})
	res := []string{}
	for _, elem := range in {
		res = append(res, elem.(string))
	}
	return res
}

func (c *Claims) Claims() map[string]interface{} {
	return c.rawClaims
}

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
func GetUserInfo(ctx context.Context, provider IdProvider, tokenSource oauth2.TokenSource) (*UserInfo, error) {

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
		return nil, &svc.RequestError{
			Response: resp,
			Body:     body,
			Err:      errors.Errorf("oidc: Calling UserInfo endpoint failed. body: %s", body),
		}
	}

	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, errors.Errorf("oidc: failed to decode userinfo: %v", err)
	}
	userInfo.RawClaims = body
	return &userInfo, nil
}
