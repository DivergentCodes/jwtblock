package web

import (
	"fmt"

	"github.com/swaggest/openapi-go/openapi3"
)

// Generate the OpenAPI spec for the service.
func GenerateOpenAPI(format string) (string, error) {
	reflector := openapi3.Reflector{}

	// Declare security scheme.
	securityName := "bearer_token"
	reflector.SpecEns().SetHTTPBearerTokenSecurity(securityName, "JWT", "Access token")

	// Endpoints
	blockGenerateOpenAPI(&reflector)
	checkGenerateOpenAPI(&reflector)

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
