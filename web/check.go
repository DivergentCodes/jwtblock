package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"divergent.codes/jwt-block/internal/blocklist"
	"divergent.codes/jwt-block/internal/cache"
	"divergent.codes/jwt-block/internal/core"
	"github.com/spf13/viper"
)

// Handler for /blocklist/check
func jwtCheck(w http.ResponseWriter, r *http.Request) {
	logger := core.GetLogger()
	var result blocklist.CheckResult

	// Only allow POST.
	if r.Method != http.MethodPost {
		WriteErrorResponse(w, ErrHttpMethodOnlyPost.Error(), http.StatusMethodNotAllowed)
		return
	}

	// Request parsing.
	var payload JwtRequestBody
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil || (payload.Jwt == "" && payload.Sha256 == "") {
		WriteErrorResponse(w, ErrMissingInvalidToken.Error(), http.StatusBadRequest)
	}

	logger.Debugw(
		"Blocklist check",
		"request_jwt", payload.Jwt,
		"request_sha256", payload.Sha256,
	)

	// Blocklist lookup by JWT or sha256.
	redisDB := cache.GetRedisClient()
	if payload.Jwt != "" {
		result, err = blocklist.CheckByJwt(redisDB, payload.Jwt)
	} else if payload.Sha256 != "" {
		result, err = blocklist.CheckBySha256(redisDB, payload.Sha256)
	}

	// Handle errors.
	if err != nil {
		logger.Debugw(
			"Web token check error",
			"err", err.Error(),
		)
		if strings.Contains(err.Error(), "Cache") {
			httpStatus := http.StatusInternalServerError
			WriteErrorResponse(w, blocklist.ErrMisconfiguredCache.Error(), httpStatus)
		} else {
			httpStatus := http.StatusBadRequest
			WriteErrorResponse(w, err.Error(), httpStatus)
		}
		return
	}

	// Response.
	w.Header().Set("Content-Type", "application/json")
	if result.IsBlocked {
		status_code := viper.GetInt(core.OptStr_HttpStatusOnBlocked)
		w.WriteHeader(status_code)
	} else {
		status_code := viper.GetInt(core.OptStr_HttpStatusOnAllowed)
		w.WriteHeader(status_code)
	}
	json.NewEncoder(w).Encode(result)
}
