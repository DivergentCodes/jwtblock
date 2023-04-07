package web

import (
	"fmt"
	"net/http"
)

// Handler for / (index)
func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "API index")
}
