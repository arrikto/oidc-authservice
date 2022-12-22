package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"k8s.io/apiserver/pkg/authentication/user"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/arrikto/oidc-authservice/common"
)

// ExternalAuthorizer is responsible for handling authorization in an external
// authorization server.
type ExternalAuthorizer struct {
	url string
}

// AuthorizationRequestBody is the object with the current request metadata that
// the ExternalAuthorizer will send to external authorizer.
type AuthorizationRequestBody struct {
	Timestamp string                   `json:"timestamp"`
	User      AuthorizationUserInfo    `json:"user"`
	Request   AuthorizationRequestInfo `json:"request"`
}

// AuthorizationUserInfo is the sub-object with the user metadata that the
// ExternalAuthorizer will send to the external authorizer.
type AuthorizationUserInfo struct {
	Name   string                 `json:"name"`
	Id     string                 `json:"id"`
	Groups []string               `json:"groups"`
	Extra  map[string][]string    `json:"extra"`
	Claims map[string]interface{} `json:"claims"`
}

// AuthorizationRequestInfo is the sub-object with the request metadata that the
// ExternalAuthorizer will send to the external authorizer.
type AuthorizationRequestInfo struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
	Method string `json:"method"`
}

func (e ExternalAuthorizer) Authorize(r *http.Request, userinfo user.Info) (allowed bool, reason string, err error) {
	// Collect data and create the AuthorizationRequestBody.
	logger := common.LoggerForRequest(r, "external authorizer")
	logger = logger.WithField("user", userinfo)
	authorizationUserInfo := e.getUserInfo(r, userinfo)

	request := e.getRequestInfo(r)
	timestamp := time.Now().Format(time.RFC3339)
	body := AuthorizationRequestBody{
		Timestamp: timestamp,
		User:      authorizationUserInfo,
		Request:   request,
	}
	// Send the request to the external authorizer.
	code, responseBody, err := e.doRequest(body)
	if err != nil {
		return false, "Error while authorizing the request", err
	}
	// If the response of the external authorizer is in the [200, 300) range
	// allow the request.
	if code >= 200 && code < 300 {
		logger.Infof("Request is allowed")
		return true, "", nil
	} else if code == 401 || code == 403 {
		logger.Infof("Request is not allowed")
		return false, fmt.Sprintf("%v", responseBody), nil
	}

	err = errors.New(fmt.Sprintf("Authorization server returned unexpected status code: %d with body: %v",
		code, responseBody))
	return false, "", err
}

// getUserInfo creates a AuthorizationUserInfo object for the current context.
func (e ExternalAuthorizer) getUserInfo(r *http.Request, userinfo user.Info) AuthorizationUserInfo {
	// Parse the JWT token and add get the claims if it exists.
	bearer := common.GetBearerToken(r.Header.Get("Authorization"))
	var parsedJwt map[string]interface{} = nil
	if bearer != "" {
		jwt, err := common.ParseJWT(bearer)
		if err == nil {
			// Unmarshal the JSON to the interface.
			err = json.Unmarshal(jwt, &parsedJwt)
			// Ignore any errors
		}
	}
	return AuthorizationUserInfo{
		Name:   userinfo.GetName(),
		Id:     userinfo.GetUID(),
		Groups: userinfo.GetGroups(),
		Extra:  userinfo.GetExtra(),
		Claims: parsedJwt,
	}
}

// getRequestInfo creates a AuthorizationRequestInfo object for the current 
// context.
func (e ExternalAuthorizer) getRequestInfo(r *http.Request) (request AuthorizationRequestInfo) {
	host := strings.Split(r.Host, ":")
	// Use 80 as a fallback.
	var port = 80
	if len(host) > 1 {
		port, _ = strconv.Atoi(host[1])
	}
	hostname := host[0]
	return AuthorizationRequestInfo{
		Host:   hostname,
		Port:   port,
		Path:   r.URL.Path,
		Method: r.Method,
	}
}

// doRequest does the request to the external authorization server.
func (e ExternalAuthorizer) doRequest(requestBody AuthorizationRequestBody) (code int, responseBody string, err error) {
	// Serialize the object.
	b, err := json.Marshal(&requestBody)
	if err != nil {
		return 0, "", err
	}
	// Send the request
	resp, err := http.Post(e.url, "application/json", bytes.NewBuffer(b))
	if err != nil {
		err = fmt.Errorf("error sending the request: %w", err)
		return 0, "", err
	}
	defer resp.Body.Close()
	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("error while reading the body: %w", err)
		return 0, "", err
	}
	return resp.StatusCode, string(response), nil
}
