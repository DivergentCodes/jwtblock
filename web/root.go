/*
Web API for the JWT blocklist.
*/

package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	"divergent.codes/jwt-block/internal/core"
)

type JwtRequestBody struct {
	Jwt    string `json:"jwt"`
	Sha256 string `json:"sha256"`
}

type StandardResponse struct {
	Message string `json:"message"`
	IsError bool   `json:"error"`
}

// Standard JSON success response.
func WriteSuccessResponse(w http.ResponseWriter, message string, httpStatus int) {
	data := StandardResponse{
		Message: message,
		IsError: false,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(data)
}

// Standard JSON error response.
func WriteErrorResponse(w http.ResponseWriter, errorMessage string, httpStatus int) {
	logger := core.GetLogger()
	logger.Errorw(errorMessage)

	data := StandardResponse{
		Message: errorMessage,
		IsError: true,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(data)
}

// Root request handler.
func HandleRequests(host string, port int) {
	logger := core.GetLogger()

	http.HandleFunc("/", index)
	http.HandleFunc("/blocklist/block", jwtBlock)
	http.HandleFunc("/blocklist/check", jwtCheck)

	logger.Infow(
		"Serving web API",
		"host", host,
		"port", port,
	)

	var netaddr = fmt.Sprintf("%s:%d", host, port)
	logger.Fatal(http.ListenAndServe(netaddr, nil))
}
