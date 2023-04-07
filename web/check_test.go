package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"divergent.codes/jwt-block/internal/blocklist"
	"divergent.codes/jwt-block/internal/crypto"
)

func Test_Check_ValidTokenAllowed_Success(t *testing.T) {
	setupMockRedis()

	httpMethod := "POST"
	urlPath := "/blocklist/check"
	tokenString := generateTokenStringHS256(30)

	// Request payload creation.
	payloadJSON, _ := json.Marshal(map[string]string{"jwt": tokenString})
	payloadBytes := bytes.NewBuffer(payloadJSON)

	// Build the request.
	request := httptest.NewRequest(httpMethod, urlPath, payloadBytes)
	w := httptest.NewRecorder()

	// Issue HTTP request to handler.
	jwtCheck(w, request)

	// Process the result.
	response := w.Result()

	body, _ := io.ReadAll(response.Body)
	var result blocklist.CheckResult
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
	if result.IsError || result.IsBlocked || result.Message != blocklist.SuccessTokenIsAllowed {
		t.Errorf(
			"Expected request to pass: status=%d, message='%s', blocked=%t, error=%t\n",
			response.StatusCode,
			result.Message,
			result.IsBlocked,
			result.IsError,
		)
	}

	teardownMockRedis()
}

func Test_Check_ValidHashAllowed_Success(t *testing.T) {
	setupMockRedis()

	httpMethod := "POST"
	urlPath := "/blocklist/check"
	tokenString := generateTokenStringHS256(30)
	hashString := crypto.Sha256FromString(tokenString)

	// Request payload creation.
	payloadJSON, _ := json.Marshal(map[string]string{"sha256": hashString})
	payloadBytes := bytes.NewBuffer(payloadJSON)

	// Build the request.
	request := httptest.NewRequest(httpMethod, urlPath, payloadBytes)
	w := httptest.NewRecorder()

	// Issue HTTP request to handler.
	jwtCheck(w, request)

	// Process the result.
	response := w.Result()

	body, _ := io.ReadAll(response.Body)
	var result blocklist.CheckResult
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
	if result.IsError || result.IsBlocked || result.Message != blocklist.SuccessTokenIsAllowed {
		t.Errorf(
			"Expected request to pass: status=%d, message='%s', blocked=%t, error=%t\n",
			response.StatusCode,
			result.Message,
			result.IsBlocked,
			result.IsError,
		)
	}

	teardownMockRedis()
}
