package web

import (
	"fmt"

	"github.com/divergentcodes/jwt-block/internal/core"
	"github.com/swaggest/openapi-go/openapi3"
)

// Generate the OpenAPI spec for the service.
func GenerateOpenAPI(format string) (string, error) {
	reflector := openapi3.Reflector{}

	// Basic info.
	reflector.Spec = &openapi3.Spec{
		Openapi: "3.0.3",
	}
	reflector.Spec.Info.
		WithTitle("JWT Block").
		WithVersion(core.Version).
		WithDescription("API of the JWT Block service")

	// Base URL.
	server := openapi3.Server{
		URL: "http://jwtblock.localhost",
	}
	reflector.Spec.Servers = append(reflector.Spec.Servers, server)

	// Declare security scheme.
	securityName := "bearerToken"
	reflector.Spec.SetHTTPBearerTokenSecurity(securityName, "JWT", "Access token")
	reflector.Spec.WithSecurity(map[string][]string{securityName: {}})

	// Endpoints.
	blockGenerateOpenAPI(&reflector)
	checkGenerateOpenAPI(&reflector)

	// Dump the schema.
	var schema []byte
	var err error
	if format == "json" {
		schema, err = reflector.Spec.MarshalJSON()
	} else if format == "yaml" {
		schema, err = reflector.Spec.MarshalYAML()
	} else {
		return "", fmt.Errorf("invalid OpenAPI output format: %s", format)
	}
	if err != nil {
		return "", err
	}
	return string(schema), nil
}
