package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
)

var (
	ErrMalformedSha256 = errors.New("Malformed sha256")
)

func Sha256FromString(value string) string {
	h := sha256.New()
	h.Write([]byte(value))
	bs := h.Sum(nil)
	sha256Hash := fmt.Sprintf("%x", bs)
	return sha256Hash
}

func IsValidSha256(value string) error {
	re := regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
	if !re.MatchString(value) {
		return ErrMalformedSha256
	}
	return nil
}
