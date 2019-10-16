// Copyright © 2019 Arrikto Inc.  All Rights Reserved.

package e2e

import (
	"net/http"
	"testing"
)

func TestUnauthorizedRequest(t *testing.T) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://localhost:8080/")
	if err != nil {
		t.Fatalf("Error contacting authservice, %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Wrong HTTP StatusCode. Got %v. Expected %v.", resp.StatusCode, http.StatusFound)
	}
}
