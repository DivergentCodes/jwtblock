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

// Handle API Gateway V1 (REST) request events
func handleHttpProxyEventV1(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	logger := core.GetLogger()
	var response events.APIGatewayProxyResponse
	responseHeaders := make(map[string]string)
	httpMethod := strings.ToUpper(event.HTTPMethod)
	origin, _ := getHeaderValue(event.Headers, "origin")

	// Handle CORS preflight requests.
	if strings.EqualFold(httpMethod, http.MethodOptions) {
		logger.Debugw(
			"received OPTIONS preflight request",
			"func", "awslambda.handleHttpProxyEventV1",
		)
		response = events.APIGatewayProxyResponse{
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
			"func", "awslambda.handleHttpProxyEventV1",
			"method", httpMethod,
		)
		response = events.APIGatewayProxyResponse{
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
			"func", "awslambda.handleHttpProxyEventV1",
			"tokenError", tokenErr.Error(),
		)
		response = events.APIGatewayProxyResponse{
			StatusCode: http.StatusUnauthorized,
			Headers:    responseHeaders,
			Body:       tokenErr.Error(),
		}
		return response, tokenErr
	}
	logger.Debugw(
		"Received value to add",
		"func", "awslambda.handleHttpProxyEventV1",
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
			"Error adding token to blocklist",
			"func", "awslambda.handleHttpProxyEventV1",
			"result", blockResult,
			"err", err,
		)
		jsonData, err := json.Marshal(blockResult)
		response = events.APIGatewayProxyResponse{
			StatusCode: httpStatus,
			Headers:    responseHeaders,
			Body:       string(jsonData),
		}
		return response, err
	}

	// Successful block
	jsonData, err := json.Marshal(blockResult)
	if err != nil {
		errMsg := "Error marshaling blockResult to JSON"
		logger.Errorw(
			errMsg,
			"func", "awslambda.handleHttpProxyEventV1",
			"err", err,
		)
		response = events.APIGatewayProxyResponse{
			StatusCode: http.StatusInternalServerError,
			Headers:    responseHeaders,
			Body:       errMsg,
		}
		return response, err
	}
	response = events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    responseHeaders,
		Body:       string(jsonData),
	}

	return response, nil
}
