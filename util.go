// Copyright (c) 2018 Antti Myyrä
// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
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

func returnStatus(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.WriteHeader(statusCode)
	w.Write([]byte(errorMsg))
}

func getEnvOrDefault(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		log.Println("No ", key, " specified, using '"+fallback+"' as default.")
		return fallback
	}
	return value
}

func getURLEnvOrDie(URLEnv string) *url.URL {
	envContent := os.Getenv(URLEnv)
	parsedURL, err := url.Parse(envContent)
	if err != nil {
		log.Fatal("Not a valid URL for env variable ", URLEnv, ": ", envContent, "\n")
	}

	return parsedURL
}

func getEnvOrDie(envVar string) string {
	envContent := os.Getenv(envVar)

	if len(envContent) == 0 {
		log.Fatal("Env variable ", envVar, " missing, exiting.")
	}

	return envContent
}

func clean(s []string) []string {
	res := []string{}
	for _, elem := range s {
		if elem != "" {
			res = append(res, elem)
		}
	}
	return res
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
