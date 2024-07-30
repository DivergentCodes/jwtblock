package awslambda

import (
	"strconv"
	"strings"

	"github.com/divergentcodes/jwtblock/internal/core"
	"github.com/spf13/viper"
)

// Write a CORS preflight response depending on the Origin header.
func makeCorsPreflightHeaders(origin string, headers map[string]string) map[string]string {
	logger := core.GetLogger()

	corsAllowed, allowedOrigin := isCorsRequestAllowed(origin)
	if corsAllowed {
		logger.Debugw(
			"cors preflight response allow headers added",
			"func", "makeCorsPreflightHeaders",
			"origin", allowedOrigin,
		)
		return addCorsResponseHeaders(headers, allowedOrigin)
	} else {
		logger.Debugw(
			"cors preflight response headers not added",
			"func", "makeCorsPreflightHeaders",
		)
	}
	return nil
}

// Add CORS allow response headers for given origin.
func addCorsResponseHeaders(headers map[string]string, origin string) map[string]string {
	corsMaxSeconds := viper.GetViper().GetInt(core.OptStr_HttpCorsMaxSeconds)

	headers["Access-Control-Allow-Origin"] = origin
	headers["Access-Control-Allow-Credentials"] = "true"
	headers["Access-Control-Allow-Headers"] = "Authorization,Accept,Origin,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Content-Range,Range"
	headers["Access-Control-Allow-Methods"] = "OPTIONS,GET,POST"
	headers["Access-Control-Max-Age"] = strconv.Itoa(corsMaxSeconds)

	return headers
}

// Check if a request's origin is configured for CORS.
func isCorsRequestAllowed(origin string) (bool, string) {
	logger := core.GetLogger()

	allowedOrigin := isCorsAllowedOrigin(origin)
	if allowedOrigin != "" {
		logger.Debugw(
			"request origin allowed for CORS",
			"func", "isCorsRequestAllowed",
			"origin", allowedOrigin,
		)
		return true, allowedOrigin
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
		if strings.EqualFold(value, origin) {
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
