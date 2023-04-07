package blocklist

import (
	"github.com/redis/go-redis/v9"

	"divergent.codes/jwt-block/internal/core"
)

type ListResult struct {
	TokenHashes []string `json:"token_hashes"`
	Size        int64    `json:"size"`
	IsError     bool     `json:"error"`
}

func List(redisDB *redis.Client) (*ListResult, error) {
	logger := core.GetLogger()
	result := &ListResult{
		Size:    -1,
		IsError: false,
	}

	size, err := Size(redisDB)
	if err != nil {
		result.IsError = true
		return result, err
	}

	// Keys are the token hashes.
	// Getting token hashes just requires calling "KEYS."
	cacheKeys := redisDB.Keys(redisContext, "*")
	result.TokenHashes = cacheKeys.Val()
	result.Size = size

	logger.Infow("Listed token hashes in the blocklist", "size", result.Size)

	return result, nil
}
