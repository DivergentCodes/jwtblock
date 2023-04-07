package blocklist

import (
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"

	"divergent.codes/jwt-block/internal/core"
	"divergent.codes/jwt-block/internal/crypto"
)

type BlockResult struct {
	Message   string `json:"message"`
	TTL       int    `json:"block_ttl_sec"`
	TTLString string `json:"block_ttl_str"`
	IsNew     bool   `json:"is_new"`
	IsError   bool   `json:"error"`
}

func Block(redisDB *redis.Client, tokenString string) (*BlockResult, error) {
	// Add token to blocklist without an explicitly passed TTL.
	return BlockWithTTL(redisDB, tokenString, -1)
}

func BlockWithTTL(redisDB *redis.Client, tokenString string, explicitTTLSeconds int) (*BlockResult, error) {
	// Add a JWT to the blocklist. Returns whether the added value is new or not.
	// explicitTTLSeconds:
	// - <0: Default TTL.
	// - 0: Infinite TTL.
	// - >0: Expiring TTL.
	logger := core.GetLogger()
	result := &BlockResult{
		TTL:     -1,
		IsError: false,
	}

	token, err := crypto.RunJwtChecks(tokenString)
	if err != nil {
		result.IsError = true
		result.Message = err.Error()
		return result, err
	}

	// Hash the JWT for storage.
	cacheKey := crypto.Sha256FromString(tokenString)

	// Determine the TTL.
	ttlDefaultSeconds := viper.GetViper().GetInt(core.OptStr_JwtTTLDefaultSeconds)
	ttlDefault := time.Duration(ttlDefaultSeconds) * time.Second
	ttl := ttlDefault
	useTokenExp := viper.GetViper().GetBool(core.OptStr_JwtTTLUseTokenExp)

	if explicitTTLSeconds >= 0 {
		// Get TTL from function argument.
		ttl = time.Duration(explicitTTLSeconds) * time.Second
		logger.Debugw("Set token TTL from explicit function argument", "ttl", ttl.Seconds())
	} else if useTokenExp {
		// Get TTL from token EXP claim.
		ttlFromExpSeconds, err := calculateTokenTTLFromExp(token)
		if err == nil {
			// Determine TTL padding.
			ttlPaddingSeconds := viper.GetInt(core.OptStr_JwtTTLExpPaddingSeconds)
			ttl = time.Duration(ttlFromExpSeconds) * time.Second
			if ttlPaddingSeconds > 0 {
				ttl += (time.Duration(ttlPaddingSeconds) * time.Second)
			}
			logger.Debugw(
				"Set token TTL from EXP claim",
				"ttl", ttlFromExpSeconds,
				"padding", ttlPaddingSeconds,
				"total", ttl.Seconds(),
			)
		} else {
			// Fallback to the default TTL.
			ttl = ttlDefault
			logger.Debugw(
				"Fallback to default token TTL instead of EXP claim",
				"ttl", ttl.Seconds(),
				"err", err,
			)
		}
	} else {
		// Use the default TTL.
		ttl = ttlDefault
		logger.Debugw("Set token TTL from default", "ttl", ttl.Seconds())
	}

	// Zero expiration means the key has no expiration time.
	isNewValue, err := redisDB.SetNX(redisContext, cacheKey, true, ttl).Result()
	if err != nil {
		logger.Errorw("Redis SetNX error when adding new JWT", "error", err.Error())
		result.IsError = true
		result.Message = err.Error()
		return result, err
	}

	// Assemble result.
	result.Message = SuccessTokenBlocked
	if !isNewValue {
		result.Message = SuccessTokenExists
	}
	result.IsNew = isNewValue
	result.TTL = int(ttl.Seconds())
	if ttl.Seconds() == 0 {
		result.TTLString = "Inf"
	} else {
		result.TTLString = ttl.String()
	}

	return result, nil
}

func calculateTokenTTLFromExp(token jwt.Token) (int, error) {
	if token.Expiration().IsZero() {
		return -1, ErrNoExpForTTL
	}
	ttl := time.Until(token.Expiration())
	ttlSeconds := int(ttl.Seconds())
	return ttlSeconds, nil
}
