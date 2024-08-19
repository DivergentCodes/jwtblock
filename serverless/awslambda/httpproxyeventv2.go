package awslambda

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"

	"github.com/divergentcodes/jwtblock/internal/blocklist"
	"github.com/divergentcodes/jwtblock/internal/cache"
	"github.com/divergentcodes/jwtblock/internal/core"
)

// Handle API Gateway V2 (HTTP) request events
func handleHttpProxyEventV2(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	logger := core.GetLogger()
	var response events.APIGatewayV2HTTPResponse
	responseHeaders := make(map[string]string)
	httpMethod := event.RequestContext.HTTP.Method
	origin, _ := getHeaderValue(event.Headers, "origin")

	// Handle CORS preflight requests.
	if strings.EqualFold(httpMethod, http.MethodOptions) {
		logger.Debugw(
			"received OPTIONS preflight request",
			"func", "awslambda.handleHttpProxyEventV2",
		)
		response = events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusOK,
			Headers:    makeCorsPreflightHeaders(origin, responseHeaders),
		}
		return response, nil
	} else {
		responseHeaders["Content-Type"] = "application/json"
	}

	// Only allow POST.
	if !strings.EqualFold(httpMethod, http.MethodPost) {
		logger.Warnw(
			"invalid HTTP method",
			"func", "awslambda.handleHttpProxyEventV2",
			"method", httpMethod,
		)
		response = events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusMethodNotAllowed,
			Headers:    makeCorsPreflightHeaders(origin, responseHeaders),
		}
		return response, nil
	}

	// Get token from headers.
	tokenString, tokenErr := getBearerToken(event.Headers)

	// No token found in headers. Unauthorized.
	if tokenErr != nil || tokenString == "" {
		msg := "failed to get token from request headers"
		logger.Errorw(
			msg,
			"func", "awslambda.handleHttpProxyEventV2",
			"tokenError", tokenErr.Error(),
		)

		response = events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusUnauthorized,
			Headers:    makeCorsPreflightHeaders(origin, responseHeaders),
			Body:       tokenErr.Error(),
		}
		return response, tokenErr
	}
	logger.Debugw(
		"received value to add",
		"func", "awslambda.handleHttpProxyEventV2",
		"token", tokenString,
	)

	// Add value to the blocklist.
	redisClient := cache.GetRedisClient()
	blockResult, err := blocklist.Block(redisClient, tokenString)
	if err != nil {
		// Error is either token format (400), or server issue (500).
		httpStatus := http.StatusBadRequest
		if strings.Contains(strings.ToLower(err.Error()), "cache") {
			httpStatus = http.StatusInternalServerError
		}
		logger.Errorw(
			"error adding token to blocklist",
			"func", "awslambda.handleHttpProxyEventV2",
			"result", blockResult,
			"err", err,
		)
		jsonData, err := json.Marshal(blockResult)
		response = events.APIGatewayV2HTTPResponse{
			StatusCode: httpStatus,
			Headers:    makeCorsPreflightHeaders(origin, responseHeaders),
			Body:       string(jsonData),
		}
		return response, err
	}

	// Successful block
	jsonData, err := json.Marshal(blockResult)
	if err != nil {
		errMsg := "error marshaling blockResult to JSON"
		logger.Errorw(
			errMsg,
			"func", "awslambda.handleHttpProxyEventV2",
			"err", err,
		)
		response = events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    makeCorsPreflightHeaders(origin, responseHeaders),
			Body:       errMsg,
		}
		return response, err
	}
	response = events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusOK,
		Headers:    makeCorsPreflightHeaders(origin, responseHeaders),
		Body:       string(jsonData),
	}

	return response, nil
}
