package web

import (
	"net/http"
	"strings"

	"github.com/divergentcodes/jwt-block/internal/blocklist"
	"github.com/divergentcodes/jwt-block/internal/cache"
	"github.com/divergentcodes/jwt-block/internal/core"
	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"
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
	WriteSuccessResponse(r, w, result.Message, 200)
}

// OpenAPI documentation generation.
func blockGenerateOpenAPI(reflector *openapi3.Reflector) {
	logger := core.GetLogger()

	blockOp, err := reflector.NewOperationContext(http.MethodPost, "/blocklist/block")
	if err != nil {
		logger.Fatalw(err.Error())
	}

	blockOp.AddRespStructure(new(blocklist.BlockResult), func(cu *openapi.ContentUnit) { cu.HTTPStatus = http.StatusOK })

	reflector.AddOperation(blockOp)
}
