package awslambda

import (
	"strings"

	"github.com/divergentcodes/jwtblock/internal/core"
)

func getHeaderValue(headers map[string]string, headerName string) (string, bool) {
	logger := core.GetLogger()

	for key, value := range headers {
		if strings.EqualFold(headerName, key) {
			logger.Debugw(
				"Found header",
				"func", "awslambda.getHeaderValue",
				"headerName", headerName,
				"headers", headers,
			)
			return value, true
		}
	}

	logger.Debugw(
		"Did not find header",
		"func", "awslambda.getHeaderValue",
		"headerName", headerName,
		"headers", headers,
	)

	return "", false
}

func getBearerToken(headers map[string]string) (string, error) {
	logger := core.GetLogger()

	value, found := getHeaderValue(headers, "authorization")
	if !found {
		logger.Debugw(
			ErrMissingTokenHeader.Error(),
			"func", "awslambda.getBearerToken",
		)
		return value, ErrMissingTokenHeader
	}

	// Extract the bearer token value.
	substrings := strings.Split(value, " ")
	if len(substrings) != 2 {
		logger.Debugw(
			ErrMalformedBearerTokenFormat.Error(),
			"func", "awslambda.getBearerToken",
		)
		return value, ErrMalformedBearerTokenFormat
	}

	value = substrings[1]
	if value == "" {
		logger.Debugw(
			ErrMissingInvalidToken.Error(),
			"func", "awslambda.getBearerToken",
		)
		return value, ErrMissingInvalidToken
	}
	return value, nil
}
