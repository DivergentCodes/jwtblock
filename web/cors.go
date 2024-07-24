package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/divergentcodes/jwtblock/internal/core"
	"github.com/spf13/viper"
)

// Write a CORS preflight response depending on the Origin header.
func WriteCorsPreflightResponse(r *http.Request, w http.ResponseWriter) {
	logger := core.GetLogger()

	corsAllowed, allowedOrigin := isCorsRequestAllowed(r)
	if corsAllowed {
		logger.Debugw(
			"cors preflight response allow headers added",
			"func", "writeCorsPreflightResponse",
			"origin", allowedOrigin,
		)
		addCorsResponseHeaders(w, allowedOrigin)
	} else {
		logger.Debugw(
			"cors preflight response headers not added",
			"func", "writeCorsPreflightResponse",
		)
	}

	w.WriteHeader(http.StatusNoContent)
}

// Add CORS allow response headers for given origin.
func addCorsResponseHeaders(w http.ResponseWriter, origin string) {
	corsMaxSeconds := viper.GetViper().GetInt(core.OptStr_HttpCorsMaxSeconds)

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization,Accept,Origin,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Content-Range,Range")
	w.Header().Set("Access-Control-Allow-Methods", "OPTIONS,GET,POST")
	w.Header().Set("Access-Control-Max-Age", strconv.Itoa(corsMaxSeconds))
}

// Get the Origin header, if it exists.
func getOriginHeader(r *http.Request) (string, error) {
	logger := core.GetLogger()

	// Get client origin from request.
	originHeaderValueList, ok := r.Header["Origin"]
	if !ok {
		logger.Debugw(
			"Preflight request has no origin",
			"func", "getOriginHeader",
		)
		return "", errors.New("request has no origin header")
	}
	originHeaderValue := originHeaderValueList[len(originHeaderValueList)-1]
	return originHeaderValue, nil
}

// Check if a request's origin is configured for CORS.
func isCorsRequestAllowed(r *http.Request) (bool, string) {
	logger := core.GetLogger()

	originHeader, err := getOriginHeader(r)
	if err == nil {
		logger.Debugw(
			"found request origin header",
			"func", "isCorsRequestAllowed",
			"origin", originHeader,
		)
		allowedOrigin := isCorsAllowedOrigin(originHeader)
		if allowedOrigin != "" {
			logger.Debugw(
				"request origin allowed for CORS",
				"func", "isCorsRequestAllowed",
				"origin", allowedOrigin,
			)
			return true, allowedOrigin
		}
	}
	return false, ""
}

// Check if an origin is configured for CORS.
func isCorsAllowedOrigin(origin string) string {
	logger := core.GetLogger()

	// Get client origins that are allowed.
	allowedOriginsList := getCorsAllowedOrigins()

	for _, value := range allowedOriginsList {
		logger.Debugw(
			"Comparing to allowed CORS origin",
			"requestOrigin", origin,
			"allowedOrigin", value,
		)
		// Allow if wildcard is in the list.
		if value == "*" {
			logger.Debugw(
				"Wildcard preflight CORS origin allowed",
				"func", "isCorsAllowedOrigin",
				"origin", "*",
			)
			return "*"
		}
		// Allow if origin is in the list.
		if value == origin {
			logger.Debugw(
				"Request preflight CORS origin allowed",
				"func", "isCorsAllowedOrigin",
				"origin", origin,
			)
			return origin
		}
	}

	// Wildcard and origin not allowed, so deny.
	return ""
}

// Get the list of allowed CORS origins.
func getCorsAllowedOrigins() []string {
	allowedOrigins := viper.GetString(core.OptStr_HttpCorsAllowedOrigins)
	allowedOriginList := strings.Split(allowedOrigins, ",")

	return allowedOriginList
}
