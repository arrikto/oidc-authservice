package oidc

import (
	"context"
	"net/url"
	"time"

	"github.com/coreos/go-oidc"
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
