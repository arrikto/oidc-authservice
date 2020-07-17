package common

import (
	"fmt"
	"net/http"
)

// RequestError is an error returned when an HTTP request goes wrong.
// For example, an error status code is returned.
type RequestError struct {
	// Response is the HTTP Response struct
	Response *http.Response
	// Body is the bytes parsed from the Response struct. This must be done
	// by the party making the HTTP request.
	Body []byte
}

var _ error = &RequestError{}

func NewRequestError(resp *http.Response, body []byte) error {
	return &RequestError{
		Body:     body,
		Response: resp,
	}
}

func (e *RequestError) Error() string {
	// We don't log the body by default, because it can potentially contain
	// security-sensitive information.
	return fmt.Sprintf("An HTTP request went wrong. Status Code: %d",
		e.Response.StatusCode)
}
