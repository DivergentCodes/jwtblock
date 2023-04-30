package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/divergentcodes/jwt-block/internal/blocklist"
)

func Test_Block_ValidTokenAndHash_Success(t *testing.T) {
	setupMockRedis()

	httpMethod := "POST"
	urlPath := "/blocklist/block"
	tokenString := generateTokenStringHS256(30)
	bearerTokenString := fmt.Sprintf("Bearer %s", tokenString)

	// Build the request.
	request := httptest.NewRequest(httpMethod, urlPath, nil)
	request.Header.Add("Authorization", bearerTokenString)
	w := httptest.NewRecorder()

	// Issue HTTP request to handler.
	jwtBlock(w, request)

	// Process the result.
	response := w.Result()

	body, _ := io.ReadAll(response.Body)
	var result StandardResponse
	err := json.Unmarshal([]byte(body), &result)
	if err != nil {
		t.Errorf("Expected request to pass: err=%s", err)
	}
	expectedStatus := 200
	if response.StatusCode != expectedStatus {
		t.Errorf(
			"Unexpected status code: actual=%d, expected=%d",
			response.StatusCode,
			expectedStatus,
		)
	}
	if result.IsError || result.Message != blocklist.SuccessTokenBlocked {
		t.Errorf(
			"Expected request to pass: status=%d, message='%s', error=%t\n",
			response.StatusCode,
			result.Message,
			result.IsError,
		)
	}

	// Issue a second HTTP request to handler to verify duplicate behavior.
	request2 := httptest.NewRequest(httpMethod, urlPath, nil)
	request2.Header.Add("Authorization", bearerTokenString)
	w2 := httptest.NewRecorder()
	jwtBlock(w2, request2)

	// Process the result.
	response2 := w2.Result()

	body2, _ := io.ReadAll(response2.Body)
	var result2 StandardResponse
	err = json.Unmarshal([]byte(body2), &result2)
	if err != nil {
		t.Errorf("Expected request to pass: err=%s", err)
	}
	if response2.StatusCode != expectedStatus {
		t.Errorf(
			"Unexpected status code: actual=%d, expected=%d",
			response2.StatusCode,
			expectedStatus,
		)
	}
	if result2.IsError || result2.Message != blocklist.SuccessTokenExists {
		t.Errorf(
			"Expected request to pass: status=%d, message='%s', error=%t\n",
			response2.StatusCode,
			result2.Message,
			result2.IsError,
		)
	}

	teardownMockRedis()
}

func Test_Block_MissingToken_Error(t *testing.T) {
	setupMockRedis()

	httpMethod := "POST"
	urlPath := "/blocklist/block"

	// Request payload creation.
	payloadJSON, _ := json.Marshal(map[string]string{})
	payloadBytes := bytes.NewBuffer(payloadJSON)

	// Build the request.
	request := httptest.NewRequest(httpMethod, urlPath, payloadBytes)
	w := httptest.NewRecorder()

	// Issue HTTP request to handler.
	jwtBlock(w, request)

	// Process the result.
	response := w.Result()

	body, _ := io.ReadAll(response.Body)
	var result StandardResponse
	err := json.Unmarshal([]byte(body), &result)
	if err != nil {
		t.Errorf("Expected request to pass: err=%s", err)
	}
	expectedStatus := 401
	if response.StatusCode != expectedStatus {
		t.Errorf(
			"Unexpected status code: actual=%d, expected=%d",
			response.StatusCode,
			expectedStatus,
		)
	}

	teardownMockRedis()
}

func Test_Block_MalformedToken_Error(t *testing.T) {
	setupMockRedis()

	httpMethod := "POST"
	urlPath := "/blocklist/block"

	// Request payload creation.
	payloadJSON, _ := json.Marshal(map[string]string{"jwt": "foobar"})
	payloadBytes := bytes.NewBuffer(payloadJSON)

	// Build the request.
	request := httptest.NewRequest(httpMethod, urlPath, payloadBytes)
	w := httptest.NewRecorder()

	// Issue HTTP request to handler.
	jwtBlock(w, request)

	// Process the result.
	response := w.Result()

	body, _ := io.ReadAll(response.Body)
	var result StandardResponse
	err := json.Unmarshal([]byte(body), &result)
	if err != nil {
		t.Errorf("Expected request to pass: err=%s", err)
	}
	expectedStatus := 401
	if response.StatusCode != expectedStatus {
		t.Errorf(
			"Unexpected status code: actual=%d, expected=%d",
			response.StatusCode,
			expectedStatus,
		)
	}

	teardownMockRedis()
}

func Test_Block_InvalidHttpMethod_Error(t *testing.T) {
	setupMockRedis()

	httpMethod := "PUT"
	urlPath := "/blocklist/block"
	tokenString := generateTokenStringHS256(30)
	bearerTokenString := fmt.Sprintf("Bearer %s", tokenString)

	// Build the request.
	request := httptest.NewRequest(httpMethod, urlPath, nil)
	request.Header.Add("Authorization", bearerTokenString)
	w := httptest.NewRecorder()

	// Issue HTTP request to handler.
	jwtBlock(w, request)

	// Process the result.
	response := w.Result()

	body, _ := io.ReadAll(response.Body)
	var result StandardResponse
	err := json.Unmarshal([]byte(body), &result)
	if err != nil {
		t.Errorf("Expected request to pass: err=%s", err)
	}
	expectedStatus := 405
	if response.StatusCode != expectedStatus {
		t.Errorf(
			"Unexpected status code: actual=%d, expected=%d",
			response.StatusCode,
			expectedStatus,
		)
	}
	if !result.IsError || result.Message != ErrHttpMethodOnlyPost.Error() {
		t.Errorf(
			"Expected ErrMissingInvalidToken: status=%d, message='%s', error=%t\n",
			response.StatusCode,
			result.Message,
			result.IsError,
		)
	}

	teardownMockRedis()
}

func generateTokenStringHS256(ttlSeconds int) string {
	// Generate the token headers.
	tokenHeaders := jws.NewHeaders()
	tokenHeaders.Set("typ", "JWT")

	// Generate the token body, with the given EXP claim.
	var tokenBody jwt.Token
	if ttlSeconds >= 0 {
		ttl := time.Duration(ttlSeconds) * time.Second
		expiration := time.Now().Add(ttl)
		tokenBody, _ = jwt.NewBuilder().
			Issuer(`some-issuer`).
			Expiration(expiration).
			Build()
	} else {
		tokenBody, _ = jwt.NewBuilder().
			Issuer(`some-issuer`).
			Build()
	}
	tokenBodyBytes, _ := jwt.NewSerializer().Serialize(tokenBody)

	// Generate the signed, finished HS256 token.
	key, _ := jwk.FromRaw([]byte(`foobar`))
	tokenBytes, _ := jws.Sign(
		tokenBodyBytes,
		jws.WithKey(jwa.HS256, key, jws.WithProtectedHeaders(tokenHeaders)),
	)
	tokenString := string(tokenBytes)
	return tokenString
}
