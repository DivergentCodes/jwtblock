package blocklist

import (
	"github.com/redis/go-redis/v9"

	"divergent.codes/jwt-block/internal/crypto"
)

type CheckResult struct {
	Message   string `json:"message"`
	IsBlocked bool   `json:"blocked"`
	TTL       int    `json:"block_ttl_sec"`
	TTLString string `json:"block_ttl_str"`
	IsError   bool   `json:"error"`
}

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
