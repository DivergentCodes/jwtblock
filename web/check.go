package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/viper"

	"github.com/divergentcodes/jwt-block/internal/blocklist"
	"github.com/divergentcodes/jwt-block/internal/cache"
	"github.com/divergentcodes/jwt-block/internal/core"
)

// Handler for /blocklist/check
func jwtCheck(w http.ResponseWriter, r *http.Request) {
	logger := core.GetLogger()
	var result blocklist.CheckResult
	var err, tokenErr, hashErr error

	httpStatusAllow := viper.GetInt(core.OptStr_HttpStatusOnAllowed)
	httpStatusDeny := viper.GetInt(core.OptStr_HttpStatusOnBlocked)

	// Check HTTP method.
	if r.Method != http.MethodGet {
		WriteErrorResponse(w, ErrHttpMethodOnlyGet.Error(), http.StatusMethodNotAllowed)
		return
	}

	// Get token or hash from headers.
	var tokenString, hashString string
	tokenString, tokenErr = parseTokenFromHeader(r)
	if tokenErr != nil {
		hashString, hashErr = parseHashFromHeader(r)
	}

	// No token or hash found in headers.
	if tokenErr != nil && hashErr != nil {
		msg := "failed to get token or hash from request headers"
		logger.Errorw(
			msg,
			"func", "web.jwtCheck",
			"tokenError", tokenErr.Error(),
			"hashError", hashErr.Error(),
		)
		DebugLogIncomingRequest(r)
		WriteErrorResponse(w, msg, httpStatusDeny)
		return
	}

	// Blocklist lookup.
	redisDB := cache.GetRedisClient()
	if tokenString != "" {
		// Lookup by JWT.
		logger.Debugw(
			"found token in Authorization HTTP header",
			"func", "web.jwtCheck",
			"token", tokenString,
		)
		result, err = blocklist.CheckByJwt(redisDB, tokenString)
	} else if hashString != "" {
		// Lookup by SHA256 hash.
		hashHeaderName := viper.GetString(core.OptStr_HttpHeaderSha256)
		msg := fmt.Sprintf("found sha256 hash in %s HTTP header", hashHeaderName)
		logger.Debugw(
			msg,
			"func", "web.jwtCheck",
			"sha256", hashString,
		)
		result, err = blocklist.CheckBySha256(redisDB, hashString)
	}

	// Handle lookup errors.
	if err != nil {
		if strings.Contains(err.Error(), "Cache") {
			// Cache error.
			logger.Errorw(
				"web token check error",
				"func", "web.jwtCheck",
				"err", err.Error(),
			)
			err = blocklist.ErrMisconfiguredCache
			httpStatus := http.StatusInternalServerError
			WriteErrorResponse(w, err.Error(), httpStatus)
		} else {
			// Operational error.
			WriteErrorResponse(w, err.Error(), httpStatusDeny)
		}
		return
	}

	// Valid response.
	w.Header().Set("Content-Type", "application/json")
	if result.IsBlocked {
		w.WriteHeader(httpStatusDeny)
	} else {
		w.WriteHeader(httpStatusAllow)
	}
	err = json.NewEncoder(w).Encode(result)
	if err != nil {
		logger.Errorw(
			"failed to JSON encode response data",
			"func", "web.jwtCheck",
			"data", result,
			"error", err,
		)
	} else {
		logger.Debugw(
			"successful lookup",
			"func", "web.jwtCheck",
			"data", result,
		)
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
