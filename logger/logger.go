package logger

import (
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

func ForRequest(r *http.Request) *log.Entry {
	return log.WithContext(r.Context()).WithFields(log.Fields{
		"ip":     getUserIP(r),
		"host":   r.Host,
		"path":   r.URL.String(),
		"method": r.Method,
	})
}

func getUserIP(r *http.Request) string {
	headerIP := r.Header.Get("X-Forwarded-For")
	if headerIP != "" {
		return headerIP
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}
