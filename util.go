// Copyright (c) 2018 Antti Myyrä
// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/user"
)

type Cacheable interface {
	getCacheKey(r *http.Request) string
}

func realpath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return path, nil
}

func loggerForRequest(r *http.Request, info string) *log.Entry {
	return log.WithContext(r.Context()).WithFields(log.Fields{
		"context": info, // include info about the module generating the log
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

func returnHTML(w http.ResponseWriter, statusCode int, html string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(statusCode)
	_, err := w.Write([]byte(html))
	if err != nil {
		log.Errorf("Failed to write body: %v", err)
	}
}

func returnMessage(w http.ResponseWriter, statusCode int, msg string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)
	_, err := w.Write([]byte(msg))
	if err != nil {
		log.Errorf("Failed to write body: %v", err)
	}
}

func returnJSONMessage(w http.ResponseWriter, statusCode int, jsonMsg interface{}) {
	jsonBytes, err := json.Marshal(jsonMsg)
	if err != nil {
		log.Errorf("Failed to marshal struct to json: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, err = w.Write(jsonBytes)
	if err != nil {
		log.Errorf("Failed to write body: %v", err)
	}
}

func deleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, MaxAge: -1, Path: "/"})
}

func createNonce(length int) (string, error) {
	// XXX: To avoid modulo bias, 256 / len(nonceChars) MUST equal 0.
	// In this case, 256 / 64 = 0. See:
	// https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
	const nonceChars = "abcdefghijklmnopqrstuvwxyz:ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789"
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	for i := range nonce {
		nonce[i] = nonceChars[int(nonce[i])%len(nonceChars)]
	}

	return string(nonce), nil
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

func userInfoToHeaders(info user.Info, opts *httpHeaderOpts, transformer *UserIDTransformer) map[string]string {
	res := map[string]string{}
	res[opts.userIDHeader] = opts.userIDPrefix + transformer.Transform(info.GetName())
	res[opts.groupsHeader] = strings.Join(info.GetGroups(), ",")
	if authMethodArr, ok := info.GetExtra()["auth-method"]; ok {
		if len(authMethodArr) > 0 && authMethodArr[0] != "" {
			res[opts.authMethodHeader] = authMethodArr[0]
		}
	}
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
