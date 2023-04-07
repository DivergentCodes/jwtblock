package blocklist

import (
	"github.com/redis/go-redis/v9"

	"divergent.codes/jwt-block/internal/core"
)

type FlushResult struct {
	Message string `json:"message"`
	Count   int64  `json:"count"`
	IsError bool   `json:"error"`
}

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
