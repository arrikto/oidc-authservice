package svc

import (
	"fmt"
	"net/http"
)

var _ error = &RequestError{}

type RequestError struct {
	Response *http.Response
	Body     []byte
	Err      error
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("status: %d, body: %s, err: %v", e.Response.StatusCode,
		e.Body, e.Err)
}

func (e *RequestError) Unwrap() error {
	return e.Err
}

var _ error = &LoginExpiredError{}

// LoginExpiredError is used by authenticators to inform the calling code
// that the provided credentials were recognized but the login has expired
type LoginExpiredError struct {
	Err error
}

func (e *LoginExpiredError) Error() string {
	return e.Err.Error()
}

func (e *LoginExpiredError) Unwrap() error {
	return e.Err
}
