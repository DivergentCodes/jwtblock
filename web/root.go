// Package web contains the web API for the JWT blocklist service.
package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/divergentcodes/jwt-block/internal/core"
	"github.com/spf13/viper"
)

// General error messages returned by the web service.
var (
	ErrHttpMethodOnlyGet  = errors.New("invalid HTTP method. Only GET is allowed")
	ErrHttpMethodOnlyPost = errors.New("invalid HTTP method. Only POST is allowed")

	ErrMissingTokenHeader = errors.New("missing HTTP header with token")
	ErrMissingHashHeader  = errors.New("missing HTTP header with hash")

	ErrMissingInvalidToken = errors.New("missing or invalid token value in request")
	ErrMissingInvalidHash  = errors.New("missing or invalid hash value in request")

	ErrMalformedBearerTokenFormat = errors.New("malformed bearer token format")
)

// A StandardResponse has the expected fields in a API response body.
type StandardResponse struct {
	Message string `json:"message"` // the response message.
	IsError bool   `json:"error"`   // whether the request resulted in an error.
}

// WriteSuccessResponse writes a HTTP success response with a StandardResponse JSON body.
func WriteSuccessResponse(r *http.Request, w http.ResponseWriter, message string, httpStatus int) {
	logger := core.GetLogger()

	data := StandardResponse{
		Message: message,
		IsError: false,
	}

	allowed, allowedOrigin := isCorsRequestAllowed(r)
	if allowed {
		addCorsResponseHeaders(w, allowedOrigin)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		logger.Errorw(
			"failed to JSON encode response data",
			"func", "WriteSuccessResponse",
			"data", data,
		)
	}
}

// WriteErrorResponse writes a HTTP error response with a StandardResponse JSON body.
func WriteErrorResponse(r *http.Request, w http.ResponseWriter, errorMessage string, httpStatus int) {
	logger := core.GetLogger()

	data := StandardResponse{
		Message: errorMessage,
		IsError: true,
	}

	corsAllowed, allowedOrigin := isCorsRequestAllowed(r)
	if corsAllowed {
		addCorsResponseHeaders(w, allowedOrigin)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		logger.Errorw(
			"failed to JSON encode response data",
			"func", "WriteErrorResponse",
			"data", data,
		)
	}
}

// HandleRequests starts the HTTP service and routes requests to individual handler functions.
func HandleRequests(host string, port int) {
	logger := core.GetLogger()

	http.HandleFunc("/", index)
	http.HandleFunc("/blocklist/block", jwtBlock)
	http.HandleFunc("/blocklist/check", jwtCheck)

	logger.Infow(
		"Serving web API",
		"func", "HandleRequests",
		"host", host,
		"port", port,
	)

	var netaddr = fmt.Sprintf("%s:%d", host, port)
	server := &http.Server{
		Addr:              netaddr,
		ReadHeaderTimeout: 3 * time.Second,
	}

	logger.Fatal(server.ListenAndServe())
}

// DebugLogIncomingRequest pretty prints the HTTP request to debug logging
func DebugLogIncomingRequest(r *http.Request) {
	logger := core.GetLogger()

	prettyReq, err := httputil.DumpRequest(r, true)
	if err != nil {
		logger.Debug(err.Error())
	} else {
		logger.Debug(string(prettyReq))
	}
}

func parseTokenFromHeader(r *http.Request) (string, error) {
	var tokenString string

	// Get the header with the bearer token.
	tokenHeaderValueList, ok := r.Header["Authorization"]
	if !ok {
		return tokenString, ErrMissingTokenHeader
	}

	// Extract the bearer token value.
	tokenHeaderValue := tokenHeaderValueList[len(tokenHeaderValueList)-1]
	substrings := strings.Split(tokenHeaderValue, " ")
	if len(substrings) != 2 {
		return tokenString, ErrMalformedBearerTokenFormat
	}

	tokenString = substrings[1]
	if tokenString == "" {
		return tokenString, ErrMissingInvalidToken
	}
	return tokenString, nil
}

func parseHashFromHeader(r *http.Request) (string, error) {
	var hashString string

	// Get the header with the hash.
	hashHeaderName := http.CanonicalHeaderKey(viper.GetString(core.OptStr_HttpHeaderSha256))
	hashHeaderValueList, ok := r.Header[hashHeaderName]
	if !ok {
		return hashString, ErrMissingTokenHeader
	}

	hashString = hashHeaderValueList[len(hashHeaderValueList)-1]
	if hashString == "" {
		return hashString, ErrMissingInvalidHash
	}
	return hashString, nil
}
