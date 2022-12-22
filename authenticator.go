package main

import (
	"net/http"
)

type Cacheable interface {
	getCacheKey(r *http.Request) string
}