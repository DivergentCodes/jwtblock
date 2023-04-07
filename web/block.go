package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"divergent.codes/jwt-block/internal/blocklist"
	"divergent.codes/jwt-block/internal/cache"
	"divergent.codes/jwt-block/internal/core"
)

var (
	ErrHttpMethodOnlyPost  = errors.New("invalid HTTP method. Only POST is allowed")
	ErrMissingInvalidToken = errors.New("missing or invalid token data in POST body")
)

// Handler for /blocklist/block
func jwtBlock(w http.ResponseWriter, r *http.Request) {
	logger := core.GetLogger()
	var result *blocklist.BlockResult

	// Only allow POST.
	if r.Method != http.MethodPost {
		WriteErrorResponse(w, ErrHttpMethodOnlyPost.Error(), http.StatusMethodNotAllowed)
		return
	}

	// Request parsing.
	var payload JwtRequestBody
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil || payload.Jwt == "" {
		WriteErrorResponse(w, ErrMissingInvalidToken.Error(), http.StatusBadRequest)
		return
	}
	logger.Debugw(
		"Received value to add",
		"jwt", payload.Jwt,
		"sha256", payload.Sha256,
	)

	// Add value to the blocklist.
	redisDB := cache.GetRedisClient()
	if payload.Jwt != "" {
		result, err = blocklist.Block(redisDB, payload.Jwt)
		if err != nil {
			httpStatus := http.StatusBadRequest
			if strings.Contains(err.Error(), "Cache") {
				httpStatus = http.StatusInternalServerError
			}
			WriteErrorResponse(w, err.Error(), httpStatus)
			return
		}
	} else if payload.Sha256 != "" {
		httpStatus := http.StatusBadRequest
		WriteErrorResponse(w, "Blocking by sha256 not implemented yet", httpStatus)
	}

	// Response.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}
