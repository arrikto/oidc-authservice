package common

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

type TlsConfig []byte

func (c *TlsConfig) Context(ctx context.Context) context.Context {
	if len(*c) == 0 {
		return ctx
	}
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		logrus.Warning("Could not load system cert pool")
		rootCAs = x509.NewCertPool()
	}
	if ok := rootCAs.AppendCertsFromPEM(*c); !ok {
		logrus.Warning("Could not append custom CA bundle, using system certs only")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: rootCAs},
	}
	tlsConf := &http.Client{Transport: tr}
	return context.WithValue(ctx, oauth2.HTTPClient, tlsConf)
}
