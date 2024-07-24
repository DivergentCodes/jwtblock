package web

import (
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/divergentcodes/jwtblock/internal/cache"
)

func setupMockRedis() {
	redisServer, _ := miniredis.Run()
	redisClient := redis.NewClient(&redis.Options{
		Addr: redisServer.Addr(),
	})

	cache.SetRedisClient(redisClient)
}

func teardownMockRedis() {
	rc := cache.GetRedisClient()
	rc.Close()
}
