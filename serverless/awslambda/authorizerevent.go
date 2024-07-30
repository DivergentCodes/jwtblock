package awslambda

import (
	"context"
	"strings"

	"github.com/aws/aws-lambda-go/events"

	"github.com/divergentcodes/jwtblock/internal/blocklist"
	"github.com/divergentcodes/jwtblock/internal/cache"
	"github.com/divergentcodes/jwtblock/internal/core"
)

// Generate an IAM policy to return in the response.
func generatePolicyResponse(principalId, effect, resourceArn string, checkResult blocklist.CheckResult) events.APIGatewayCustomAuthorizerResponse {
	logger := core.GetLogger()

	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalId}

	if effect != "" && resourceArn != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resourceArn},
				},
			},
		}
	}

	// Add check result structure to response context.
	authResponse.Context = map[string]interface{}{
		"message":       checkResult.Message,
		"blocked":       checkResult.IsBlocked,
		"block_ttl_sec": checkResult.TTL,
		"block_ttl_str": checkResult.TTLString,
		"error":         checkResult.IsError,
	}

	logger.Debugw(
		"generated authorizer response",
		"func", "generatedPolicyResponse",
		"effect", effect,
		"resourceArn", resourceArn,
		"response", authResponse,
	)

	return authResponse
}

func handleAuthorizerTypeRequestEvent(ctx context.Context, event events.APIGatewayV2CustomAuthorizerV2Request) (events.APIGatewayCustomAuthorizerResponse, error) {
	logger := core.GetLogger()

	if strings.ToLower(event.Type) != "request" {
		logger.Errorw(
			"event type is not 'token'",
			"func", "awslambda.handleAuthorizerTypeTokenEvent",
			"err", ErrLambdaAuth500AuthConfig.Error(),
		)
		return events.APIGatewayCustomAuthorizerResponse{}, ErrLambdaAuth500AuthConfig
	}

	token, tokenErr := getBearerToken(event.Headers)
	if tokenErr != nil {
		logger.Errorw(
			"token parsing failed",
			"func", "awslambda.handleAuthorizerTypeRequestEvent",
			"err", ErrLambdaAuth401Unauthorized.Error(),
		)
		return events.APIGatewayCustomAuthorizerResponse{}, ErrLambdaAuth401Unauthorized
	}
	logger.Debugw(
		"received token in Lambda event",
		"func", "awslambda.handleAuthorizerTypeRequestEvent",
		"token", token,
	)

	// Token validation and blocklist lookup.
	redisClient := cache.GetRedisClient()
	checkResult, err := blocklist.CheckByJwt(redisClient, token)
	if err != nil {
		logger.Errorw(
			"token check failed",
			"func", "awslambda.handleAuthorizerTypeRequestEvent",
			"err", err.Error(),
		)
	}

	// Response generation.
	var response events.APIGatewayCustomAuthorizerResponse
	var action string
	if checkResult.IsBlocked || err != nil {
		action = "Deny"
		// This is how to define status codes returned by AWS Lambda Authorizers.
		err = ErrLambdaAuth401Unauthorized
	} else {
		action = "Allow"
		err = nil
	}
	response = generatePolicyResponse("user", action, event.RouteArn, checkResult)
	logger.Debugw(
		"lambda authorizer response generated",
		"func", "awslambda.handleAuthorizerTypeRequestEvent",
		"action", action,
	)

	return response, err
}

func handleAuthorizerTypeTokenEvent(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	logger := core.GetLogger()

	if strings.ToLower(event.Type) != "token" {
		logger.Errorw(
			"event type is not 'token'",
			"func", "awslambda.handleAuthorizerTypeTokenEvent",
			"err", ErrLambdaAuth500AuthConfig.Error(),
		)
		return events.APIGatewayCustomAuthorizerResponse{}, ErrLambdaAuth500AuthConfig
	}
	token := event.AuthorizationToken
	if token == "" {
		logger.Errorw(
			"empty token value",
			"func", "awslambda.handleAuthorizerTypeTokenEvent",
			"err", ErrLambdaAuth401Unauthorized.Error(),
		)
		return events.APIGatewayCustomAuthorizerResponse{}, ErrLambdaAuth401Unauthorized
	}
	logger.Debugw(
		"received token in Lambda event",
		"func", "awslambda.handleAuthorizerTypeTokenEvent",
		"token", token,
	)

	// Token validation and blocklist lookup.
	redisClient := cache.GetRedisClient()
	checkResult, err := blocklist.CheckByJwt(redisClient, token)
	if err != nil {
		logger.Errorw(
			"token check failed",
			"func", "awslambda.handleAuthorizerTypeTokenEvent",
			"err", err.Error(),
		)
	}

	// Response generation.
	var response events.APIGatewayCustomAuthorizerResponse
	var action string
	if checkResult.IsBlocked || err != nil {
		action = "Deny"
		// This is how to define status codes returned by AWS Lambda Authorizers.
		err = ErrLambdaAuth401Unauthorized
	} else {
		action = "Allow"
		err = nil
	}
	response = generatePolicyResponse("user", action, event.MethodArn, checkResult)
	logger.Debugw(
		"lambda authorizer response generated",
		"func", "awslambda.handleAuthorizerTypeTokenEvent",
		"action", action,
		"err", err.Error(),
	)

	return response, err
}
