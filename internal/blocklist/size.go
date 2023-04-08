package blocklist

import (
	"github.com/redis/go-redis/v9"
)

// Size will return the number of token hashes in the blocklist.
func Size(redisDB *redis.Client) (int64, error) {
	count, err := redisDB.DBSize(redisContext).Result()
	if err != nil {
		return 0, err
	}
	return count, nil
}
