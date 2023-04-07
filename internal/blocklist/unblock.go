package blocklist

import (
	"github.com/redis/go-redis/v9"

	"divergent.codes/jwt-block/internal/crypto"
)

type UnblockResult struct {
	Message     string `json:"message"`
	IsUnblocked bool   `json:"unblocked"`
	IsError     bool   `json:"error"`
}

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
