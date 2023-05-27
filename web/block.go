package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/divergentcodes/jwt-block/internal/blocklist"
	"github.com/divergentcodes/jwt-block/internal/cache"
	"github.com/divergentcodes/jwt-block/internal/core"
)

// Handler for /blocklist/block
func jwtBlock(w http.ResponseWriter, r *http.Request) {
	logger := core.GetLogger()
	var result *blocklist.BlockResult
	var tokenString string
	var err, tokenErr error

	// Handle CORS preflight requests.
	if r.Method == http.MethodOptions {
		WriteCorsPreflightResponse(r, w)
		return
	}

	// Only allow POST.
	if r.Method != http.MethodPost {
		WriteErrorResponse(r, w, ErrHttpMethodOnlyPost.Error(), http.StatusMethodNotAllowed)
		return
	}

	// Get token from headers.
	tokenString, tokenErr = parseTokenFromHeader(r)

	// No token found in headers. Unauthorized.
	if tokenErr != nil || tokenString == "" {
		msg := "failed to get token from request headers"
		logger.Errorw(
			msg,
			"func", "web.jwtCheck",
			"tokenError", tokenErr.Error(),
		)
		DebugLogIncomingRequest(r)
		WriteErrorResponse(r, w, msg, http.StatusUnauthorized)
		return
	}
	logger.Debugw(
		"Received value to add",
		"func", "web.jwtBlock",
		"token", tokenString,
	)

	// Add value to the blocklist.
	redisDB := cache.GetRedisClient()
	result, err = blocklist.Block(redisDB, tokenString)
	if err != nil {
		// Error is either token format (400), or server issue (500).
		httpStatus := http.StatusBadRequest
		if strings.Contains(err.Error(), "Cache") {
			httpStatus = http.StatusInternalServerError
		}
		WriteErrorResponse(r, w, err.Error(), httpStatus)
		return
	}

	// Response.
	allowed, allowedOrigin := isCorsRequestAllowed(r)
	if allowed {
		addCorsResponseHeaders(w, allowedOrigin)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(result)
	if err != nil {
		logger.Errorw(
			"failed to JSON encode response data",
			"func", "web.jwtBlock",
			"data", result,
			"error", err,
		)
	}
}
