package main

import (
	"fmt"
)

var _ error = &requestError{}

type requestError struct {
	StatusCode int
	Err        error
}

func (e *requestError) Error() string {
	return fmt.Sprintf("status: %d, err: %v", e.StatusCode, e.Err)
}
