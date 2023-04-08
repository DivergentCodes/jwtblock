package blocklist

import (
	"github.com/redis/go-redis/v9"

	"divergent.codes/jwt-block/internal/crypto"
)

// A CheckResult contains the result of checking for a token in the blocklist.
type CheckResult struct {
	Message   string `json:"message"`       // message summarizing the result.
	IsBlocked bool   `json:"blocked"`       // whether or not the token is blocked (present in the blocklist).
	TTL       int    `json:"block_ttl_sec"` // remaining time-to-live of the token in the blocklist.
	TTLString string `json:"block_ttl_str"` // human readable remaining time-to-live.
	IsError   bool   `json:"error"`         // whether or not the result was an error.
}

// CheckByJwt checks if a token's hash value is in the blocklist.
//
// The passed tokenString will be hashed and looked up.
func CheckByJwt(redisDB *redis.Client, tokenString string) (CheckResult, error) {
	// Parse, validate, verify the JWT.
	var checkResult CheckResult
	_, err := crypto.RunJwtChecks(tokenString)
	if err != nil {
		return checkResult, err
	}

	key := crypto.Sha256FromString(tokenString)
	return CheckBySha256(redisDB, key)
}

// CheckBySha256 checks if the hash value of a token is in the blocklist.
func CheckBySha256(redisDB *redis.Client, sha256 string) (CheckResult, error) {
	// Verify the hash.
	var checkResult CheckResult
	err := crypto.IsValidSha256(sha256)
	if err != nil {
		return checkResult, err
	}

	// Perform lookup.
	ttl, err := redisDB.TTL(redisContext, sha256).Result()

	// Handle errors.
	if err == redis.Nil {
		return checkResult, nil
	} else if err != nil {
		return checkResult, err
	}

	// Process results.
	if ttl.Nanoseconds() == -2 {
		// Not found in the cache.
		checkResult.Message = SuccessTokenIsAllowed
		checkResult.IsBlocked = false
		checkResult.TTL = -1
		checkResult.TTLString = ""
		checkResult.IsError = false
	} else if ttl.Nanoseconds() == -1 {
		// Found, but without a TTL.
		checkResult.Message = SuccessTokenIsBlocked
		checkResult.IsBlocked = true
		checkResult.TTL = 0
		checkResult.TTLString = "Inf"
		checkResult.IsError = false
	} else {
		// Found with a defined TTL.
		checkResult.Message = SuccessTokenIsBlocked
		checkResult.IsBlocked = true
		checkResult.TTL = int(ttl.Seconds())
		checkResult.TTLString = ttl.String()
		checkResult.IsError = false
	}

	return checkResult, nil
}
