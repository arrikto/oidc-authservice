package main

import (
	"net/http"
)

type Authenticator interface {
	// Authenticate tries to authenticate a request and
	// returns a User and error if authentication fails.
	Authenticate(w http.ResponseWriter, r *http.Request) (*User, error)
}

type User struct {
	Name   string
	Groups []string
}
