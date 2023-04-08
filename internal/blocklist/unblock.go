package blocklist

import (
	"github.com/redis/go-redis/v9"

	"divergent.codes/jwt-block/internal/crypto"
)

// A UnblockResult contains the result of unblocking a token in the blocklist.
type UnblockResult struct {
	Message     string `json:"message"`   // message summarizing the result.
	IsUnblocked bool   `json:"unblocked"` // whether or not the token was unblocked (removed from the blocklist).
	IsError     bool   `json:"error"`     // whether or not the result was an error.
}

// UnblockByJwt removes a token's hash from the blocklist by first hashing the passed token.
func UnblockByJwt(redisDB *redis.Client, tokenString string) (*UnblockResult, error) {
	result := &UnblockResult{
		IsError: false,
	}

	// Allow a JWT by removing it from the blocklist.
	_, err := crypto.RunJwtChecks(tokenString)
	if err != nil {
		result.Message = err.Error()
		result.IsError = true
		return result, err
	}

	key := crypto.Sha256FromString(tokenString)
	return UnblockBySha256(redisDB, key)
}

// UnblockBySha256 removes the passed token hash from the blocklist.
func UnblockBySha256(redisDB *redis.Client, sha256 string) (*UnblockResult, error) {
	result := &UnblockResult{
		IsError: false,
	}

	// Check SHA256 validity.
	if err := crypto.IsValidSha256(sha256); err != nil {
		result.Message = crypto.ErrMalformedSha256.Error()
		result.IsError = true
		return result, crypto.ErrMalformedSha256
	}

	// Allow a JWT by removing the SHA256 from the blocklist.
	status, err := redisDB.Del(redisContext, sha256).Result()
	if err != nil {
		result.Message = err.Error()
		result.IsError = true
		return result, err
	}

	if status == 1 {
		result.Message = err.Error()
		result.IsError = true
		return result, nil
	}

	result.Message = SuccessTokenUnblocked
	if !result.IsUnblocked {
		result.Message = SuccessTokenNotExists
	}

	return result, nil
}
