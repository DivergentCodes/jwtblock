package blocklist

import (
	"github.com/redis/go-redis/v9"

	"github.com/divergentcodes/jwt-block/internal/core"
)

// A FlushResult contains the result of checking for a token in the blocklist.
type FlushResult struct {
	Message string `json:"message"` // message summarizing the result.
	Count   int64  `json:"count"`   // number of records flushed from the blocklist.
	IsError bool   `json:"error"`   // whether or not the result was an error.
}

// Flush empties the blocklist cache of all tokens, so none are blocked.
func Flush(redisDB *redis.Client) (*FlushResult, error) {
	logger := core.GetLogger()
	result := &FlushResult{
		Count:   -1,
		IsError: false,
	}

	// Get size before flush.
	count, err := Size(redisDB)
	if err != nil {
		result.IsError = true
		return result, err
	}

	// Flush the cache.
	flushResult, err := redisDB.FlushDB(redisContext).Result()
	if err != nil {
		result.IsError = true
		return result, err
	}
	result.Message = flushResult
	result.Count = count

	logger.Infow(
		"Flushed the blocklist",
		"count", count,
		"result", result,
	)

	return result, nil
}
