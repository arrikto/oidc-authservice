// Copyright (c) 2018 Antti Myyrä
// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/user"
)

func loggerForRequest(r *http.Request) *log.Entry {
	return log.WithContext(r.Context()).WithFields(log.Fields{
		"ip":      getUserIP(r),
		"request": r.URL.String(),
	})
}

func getUserIP(r *http.Request) string {
	headerIP := r.Header.Get("X-Forwarded-For")
	if headerIP != "" {
		return headerIP
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

func returnMessage(w http.ResponseWriter, statusCode int, msg string) {
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "text/plain")
	_, err := w.Write([]byte(msg))
	if err != nil {
		log.Errorf("Failed to write body: %v", err)
	}
}

func returnJSONMessage(w http.ResponseWriter, statusCode int, jsonMsg interface{}) {
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "application/json")
	jsonBytes, err := json.Marshal(jsonMsg)
	if err != nil {
		log.Errorf("Failed to marshal struct to json: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err = w.Write(jsonBytes)
	if err != nil {
		log.Errorf("Failed to write body: %v", err)
	}
}

func createNonce(length int) string {
	nonceChars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	var nonce = make([]rune, length)
	for i := range nonce {
		nonce[i] = nonceChars[rand.Intn(len(nonceChars))]
	}

	return string(nonce)
}

func setTLSContext(ctx context.Context, caBundle []byte) context.Context {
	if len(caBundle) == 0 {
		return ctx
	}
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		log.Warning("Could not load system cert pool")
		rootCAs = x509.NewCertPool()
	}
	if ok := rootCAs.AppendCertsFromPEM(caBundle); !ok {
		log.Warning("Could not append custom CA bundle, using system certs only")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: rootCAs},
	}
	tlsConf := &http.Client{Transport: tr}
	return context.WithValue(ctx, oauth2.HTTPClient, tlsConf)
}

func mustParseURL(rawURL string) *url.URL {
	url, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return url
}

func resolvePathReference(u *url.URL, p string) *url.URL {
	ret := *u
	ret.Path = path.Join(ret.Path, p)
	return &ret
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	// TODO: Consider retrying the request if response code is 503
	// See: https://tools.ietf.org/html/rfc7009#section-2.2.1
	return client.Do(req.WithContext(ctx))
}

func getBearerToken(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "Bearer ") {
		return strings.TrimPrefix(value, "Bearer ")
	}
	return value
}

func userInfoToHeaders(info user.Info, opts *httpHeaderOpts) map[string]string {
	res := map[string]string{}
	res[opts.userIDHeader] = opts.userIDPrefix + info.GetName()
	res[opts.groupsHeader] = strings.Join(info.GetGroups(), ",")
	return res
}

func interfaceSliceToStringSlice(in []interface{}) []string {
	if in == nil {
		return nil
	}

	res := []string{}
	for _, elem := range in {
		res = append(res, elem.(string))
	}
	return res
}
