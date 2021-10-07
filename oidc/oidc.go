package oidc

import (
	"context"
	"net/url"
	"time"

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
