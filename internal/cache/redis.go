// Package cache implements a standardized, pre-configured Redis cache client.
package cache

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"

	"github.com/divergentcodes/jwtblock/internal/core"
)

var once sync.Once
var redisClient *redis.Client
var redisContext context.Context

func initRedisClient() *redis.Client {
	redisHost := viper.GetString(core.OptStr_RedisHost)
	redisPort := viper.GetString(core.OptStr_RedisPort)
	tlsEnabled := viper.GetBool(core.OptStr_RedisTlsEnabled)
	tlsSkipVerify := viper.GetBool(core.OptStr_RedisTlsNoverify)

	var tlsConfig *tls.Config = nil
	if tlsEnabled {
		tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: tlsSkipVerify,
		}
	}

	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", redisHost, redisPort),
		Username: viper.GetString(core.OptStr_RedisUsername),
		Password: viper.GetString(core.OptStr_RedisPassword),
		DB:       viper.GetInt(core.OptStr_RedisDbnum),

		TLSConfig: tlsConfig,
	})

	return client
}

// GetRedisClient returns a singleton of a configured Redis client.
func GetRedisClient() *redis.Client {
	once.Do(func() {
		if redisClient == nil {
			redisClient = initRedisClient()
		}
		if redisContext == nil {
			redisContext = context.TODO()
		}
	})

	return redisClient
}

// SetRedisClient overrides and explicitly sets the Redis client singleton.
func SetRedisClient(rc *redis.Client) {
	redisClient = rc
}

// Verify that the Redis cache can be interacted with.
func IsRedisReady() (bool, error) {
	redisContext = context.TODO()
	redisDB := GetRedisClient()
	_, err := redisDB.DBSize(redisContext).Result()
	if err != nil {
		return false, err
	}
	return true, nil
}
