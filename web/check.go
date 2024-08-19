package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/viper"
	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/divergentcodes/jwtblock/internal/blocklist"
	"github.com/divergentcodes/jwtblock/internal/cache"
	"github.com/divergentcodes/jwtblock/internal/core"
)

// Handler for /blocklist/check
func jwtCheck(w http.ResponseWriter, r *http.Request) {
	logger := core.GetLogger()
	var result blocklist.CheckResult
	var err, tokenErr, hashErr error

	httpStatusAllow := viper.GetInt(core.OptStr_HttpStatusOnAllowed)
	httpStatusDeny := viper.GetInt(core.OptStr_HttpStatusOnBlocked)

	// Handle CORS preflight requests.
	if r.Method == http.MethodOptions {
		WriteCorsPreflightResponse(r, w)
		return
	}

	// Only allow GET.
	if r.Method != http.MethodGet {
		WriteErrorResponse(r, w, ErrHttpMethodOnlyGet.Error(), http.StatusMethodNotAllowed)
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
		WriteErrorResponse(r, w, msg, httpStatusDeny)
		return
	}

	// Blocklist lookup.
	redisClient := cache.GetRedisClient()
	if tokenString != "" {
		// Lookup by JWT.
		logger.Debugw(
			"found token in Authorization HTTP header",
			"func", "web.jwtCheck",
			"token", tokenString,
		)
		result, err = blocklist.CheckByJwt(redisClient, tokenString)
	} else if hashString != "" {
		// Lookup by SHA256 hash.
		hashHeaderName := viper.GetString(core.OptStr_HttpHeaderSha256)
		msg := fmt.Sprintf("found sha256 hash in %s HTTP header", hashHeaderName)
		logger.Debugw(
			msg,
			"func", "web.jwtCheck",
			"sha256", hashString,
		)
		result, err = blocklist.CheckBySha256(redisClient, hashString)
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
			WriteErrorResponse(r, w, err.Error(), httpStatus)
		} else {
			// Operational error.
			WriteErrorResponse(r, w, err.Error(), httpStatusDeny)
		}
		return
	}

	// Valid response.
	allowed, allowedOrigin := isCorsRequestAllowed(r)
	if allowed {
		addCorsResponseHeaders(w, allowedOrigin)
	}
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

// OpenAPI documentation generation.
func checkGenerateOpenAPI(reflector *openapi3.Reflector) {
	logger := core.GetLogger()

	checkOp, err := reflector.NewOperationContext(http.MethodGet, "/blocklist/check")
	if err != nil {
		logger.Fatalw(err.Error())
	}

	statusCodes := []int{http.StatusOK, http.StatusUnauthorized}
	for _, status := range statusCodes {
		checkOp.AddRespStructure(new(blocklist.CheckResult), func(cu *openapi.ContentUnit) { cu.HTTPStatus = status })
	}

	err = reflector.AddOperation(checkOp)
	if err != nil {
		logger.Fatalw(err.Error())
	}
}
