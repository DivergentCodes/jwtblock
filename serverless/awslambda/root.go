package awslambda

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/divergentcodes/jwtblock/internal/core"
)

// General error messages returned by the web service.
var (
	//lint:ignore ST1005 AWS Lambda behavior requires capitalization
	ErrLambdaAuth500AuthConfig   = errors.New("Internal Server Error")
	ErrLambdaAuth401Unauthorized = errors.New("Unauthorized")

	ErrMissingTokenHeader = errors.New("missing HTTP header with token")
	ErrMissingHashHeader  = errors.New("missing HTTP header with hash")

	ErrMissingInvalidToken = errors.New("missing or invalid token value in request")
	ErrMissingInvalidHash  = errors.New("missing or invalid hash value in request")

	ErrMalformedBearerTokenFormat = errors.New("malformed bearer token format")
)

// Entry point to handle the incoming events.
func HandleLambdaEvent(ctx context.Context, event json.RawMessage) (interface{}, error) {
	logger := core.GetLogger()

	logger.Debugw(
		"Lambda Event",
		"func", "awslambda.HandleLambdaEvent",
		"rawEvent", event,
		"rawContext", ctx,
	)

	// Check event type.
	var authorizerTypeRequestEvent events.APIGatewayV2CustomAuthorizerV2Request
	var authorizerTypeTokenEvent events.APIGatewayCustomAuthorizerRequest
	var httpProxyRequestEventV1 events.APIGatewayProxyRequest
	var httpProxyRequestEventV2 events.APIGatewayV2HTTPRequest
	if err := json.Unmarshal(event, &authorizerTypeRequestEvent); err == nil && strings.ToLower(authorizerTypeRequestEvent.Type) == "request" {
		logger.Debugw(
			"Lambda Event",
			"func", "awslambda.HandleLambdaEvent",
			"type", "authorizerTypeRequestEvent",
			"event", authorizerTypeRequestEvent,
			"context", ctx,
		)
		return handleAuthorizerTypeRequestEvent(ctx, authorizerTypeRequestEvent)
	} else if err := json.Unmarshal(event, &authorizerTypeTokenEvent); err == nil && strings.ToLower(authorizerTypeTokenEvent.Type) == "token" {
		logger.Debugw(
			"Lambda Event",
			"func", "awslambda.HandleLambdaEvent",
			"type", "authorizerTypeTokenEvent",
			"event", authorizerTypeTokenEvent,
			"context", ctx,
		)
		return handleAuthorizerTypeTokenEvent(ctx, authorizerTypeTokenEvent)
	} else if err := json.Unmarshal(event, &httpProxyRequestEventV1); err == nil && httpProxyRequestEventV1.HTTPMethod != "" {
		logger.Debugw(
			"Lambda Event",
			"func", "awslambda.HandleLambdaEvent",
			"type", "httpProxyRequestEventV1",
			"event", httpProxyRequestEventV1,
			"context", ctx,
		)
		return handleHttpProxyEventV1(ctx, httpProxyRequestEventV1)
	} else if err := json.Unmarshal(event, &httpProxyRequestEventV2); err == nil && httpProxyRequestEventV2.Version == "2.0" {
		logger.Debugw(
			"Lambda Event",
			"func", "awslambda.HandleLambdaEvent",
			"type", "httpProxyRequestEventV2",
			"event", httpProxyRequestEventV2,
			"context", ctx,
		)
		return handleHttpProxyEventV2(ctx, httpProxyRequestEventV2)
	}

	logger.Warnw(
		"Unknown Lambda event type",
		"func", "awslambda.HandleLambdaEvent",
		"event", event,
		"context", ctx,
	)
	return nil, fmt.Errorf("invalid Lambda event type")
}

// Check if the runtime environment is AWS Lambda.
func IsAwsLambdaEnv() bool {
	_, isLambda := os.LookupEnv("AWS_LAMBDA_FUNCTION_NAME")
	return isLambda
}

// Start the Lambda handler.
func Start() {
	lambda.Start(HandleLambdaEvent)
}
