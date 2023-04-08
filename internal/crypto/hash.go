package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
)

// General error messages from the hash utilities.
var (
	ErrMalformedSha256 = errors.New("malformed sha256")
)

// Get the SHA256 hash digest of a string value.
func Sha256FromString(value string) string {
	h := sha256.New()
	h.Write([]byte(value))
	bs := h.Sum(nil)
	sha256Hash := fmt.Sprintf("%x", bs)
	return sha256Hash
}

// Check if a string value is a valid SHA256 hash.
func IsValidSha256(value string) error {
	re := regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
	if !re.MatchString(value) {
		return ErrMalformedSha256
	}
	return nil
}
