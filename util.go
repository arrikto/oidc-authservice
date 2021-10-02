// Copyright (c) 2018 Antti Myyrä
// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package main

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
)

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

func userInfoToHeaders(user *User, opts *httpHeaderOpts, transformer *UserIDTransformer) map[string]string {
	res := map[string]string{}
	res[opts.userIDHeader] = opts.userIDPrefix + transformer.Transform(user.Name)
	res[opts.groupsHeader] = strings.Join(user.Groups, ",")
	return res
}
