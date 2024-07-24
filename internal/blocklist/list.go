package blocklist

import (
	"github.com/redis/go-redis/v9"

	"github.com/divergentcodes/jwtblock/internal/core"
)

// A ListResult contains the result of listing token hashes in the blocklist.
type ListResult struct {
	TokenHashes []string `json:"token_hashes"` // hashes of blocked tokens.
	Size        int64    `json:"size"`         // the number of blocked tokens.
	IsError     bool     `json:"error"`        // whether or not the result was an error.
}

// List will dump all token hashes in the cache.
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
