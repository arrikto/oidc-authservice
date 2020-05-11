package main

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// revocationEndpoint parses the OIDC Provider claims from the discovery document
// and tries to find the revocation_endpoint.
func revocationEndpoint(p *oidc.Provider) (string, error) {
	claims := struct {
		RevocationEndpoint string `json:"revocation_endpoint"`
	}{}
	if err := p.Claims(&claims); err != nil {
		return "", errors.Wrap(err, "Error unmarshalling provider doc into struct")
	}
	if claims.RevocationEndpoint == "" {
		return "", errors.New("Provider doesn't have a revocation_endpoint")
	}
	return claims.RevocationEndpoint, nil
}

// revokeTokens is a helper that takes an oauth2.Token and revokes the access and refresh tokens.
// If no tokens are found, it succeeds.
func revokeTokens(ctx context.Context, revocationEndpoint string, token *oauth2.Token, clientID, clientSecret string) error {
	if token.AccessToken != "" {
		err := revokeToken(ctx, revocationEndpoint, token.AccessToken, "access_token", clientID, clientSecret)
		if err != nil {
			return errors.Wrap(err, "Failed to revoke access token")
		}
	}
	if token.RefreshToken != "" {
		err := revokeToken(ctx, revocationEndpoint, token.AccessToken, "refresh_token", clientID, clientSecret)
		if err != nil {
			return errors.Wrap(err, "Failed to revoke refresh token")
		}
	}
	return nil
}

// revokeToken takes care of revoking an access/refresh token to the IdP.
// The revocation procedure is described in RFC7009:
// https://tools.ietf.org/html/rfc7009
func revokeToken(ctx context.Context, revocationEndpoint string, token, tokenType, clientID, clientSecret string) error {
	// Verify revocation_endpoint has https url
	if !strings.HasPrefix(revocationEndpoint, "https") {
		return errors.New(fmt.Sprintf("Revocation endpoint (%v) MUST use https", revocationEndpoint))
	}
	values := url.Values{}
	values.Set("token", token)
	values.Set("token_type_hint", tokenType)
	req, err := http.NewRequest(http.MethodPost, revocationEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// We only support basic auth now, we may need to support other methods in the future
	// See: https://github.com/golang/oauth2/blob/bf48bf16ab8d622ce64ec6ce98d2c98f916b6303/internal/token.go#L204-L215
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := doRequest(ctx, req)
	if err != nil {
		return errors.Wrap(err, "Error contacting revocation endpoint")
	}
	if code := resp.StatusCode; code != 200 {
		// Read body to include in error for debugging purposes.
		// According to RFC6749 (https://tools.ietf.org/html/rfc6749#section-5.2)
		// the body should be in JSON, if we want to parse it in the future.
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return &requestError{
				StatusCode: resp.StatusCode,
				Err:        errors.New(fmt.Sprintf("Revocation endpoint returned code %v, failed to read body: %v", code, err)),
			}
		}
		return &requestError{
			StatusCode: resp.StatusCode,
			Err:        errors.New(fmt.Sprintf("Revocation endpoint returned code %v, server returned: %v", code, body)),
		}
	}
	return nil
}
