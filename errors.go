package main

import (
	"fmt"
	"net/http"
)

var _ error = &requestError{}

type requestError struct {
	Response *http.Response
	Body     []byte
	Err      error
}

func (e *requestError) Error() string {
	return fmt.Sprintf("status: %d, body: %s, err: %v", e.Response.StatusCode,
		e.Body, e.Err)
}

func (e *requestError) Unwrap() error {
	return e.Err
}

var _ error = &loginExpiredError{}

// loginExpiredError is used by authenticators to inform the calling code
// that the provided credentials were recognized but the login has expired
type loginExpiredError struct {
	Err error
}

func (e *loginExpiredError) Error() string {
	return e.Err.Error()
}

func (e *loginExpiredError) Unwrap() error {
	return e.Err
}

// The authenticatorSpecificError type is used to inform the calling code
// that the appropriate authentication method failed to authenticate the 
// request. 
// No other authentication method needs to be tested.
type authenticatorSpecificError struct {
	Err error
}

func (e *authenticatorSpecificError) Error() string {
	return e.Err.Error()
}

func (e *authenticatorSpecificError) Unwrap() error {
	return e.Err
}
