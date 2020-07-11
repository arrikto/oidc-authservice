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
