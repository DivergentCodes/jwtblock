package crypto

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"

	"github.com/divergentcodes/jwtblock/internal/core"
)

// General error messages from JWT utilities.
var (
	cacheInstance *jwk.Cache
	once          sync.Once

	ErrJwtVerificationKeyNotSet = errors.New("no key set for JWT verification")
)

// getJwksCache returns the singleton instance of the JWK cache.
func getJwksCache() *jwk.Cache {
	logger := core.GetLogger()
	once.Do(func() {
		ctx, _ := context.WithCancel(context.Background())
		cacheInstance = jwk.NewCache(ctx)
		jwksUrl := viper.GetString(core.OptStr_JwtVerifyJwksUrl)
		cacheInstance.Register(
			jwksUrl,
			jwk.WithMinRefreshInterval(15*time.Minute),
		)

		jwksSet, err := cacheInstance.Refresh(ctx, jwksUrl)
		if err != nil {
			fmt.Printf("failed to initially refresh JWKS URL: %s\n", err)
			return
		}

		logger.Debugw(
			"jwks cache instantiated",
			"func", "crypto.getJwksCache",
			"jwksUrl", jwksUrl,
			"jwksSet", jwksSet,
		)
	})
	return cacheInstance
}

func getJwtParserOptions() ([]jwt.ParseOption, error) {
	logger := core.GetLogger()

	// Set the JWT parser options based on configuration values.
	var err error

	// Configure the JWT parser.
	doValidate := viper.GetBool(core.OptStr_JwtValidateEnabled)
	doVerify := viper.GetBool(core.OptStr_JwtVerifyEnabled)
	requireExp := viper.GetBool(core.OptStr_JwtTTLRequireTokenExp)

	var jwtParseOptions = []jwt.ParseOption{
		jwt.WithValidate(doValidate),
		jwt.WithVerify(doVerify),
	}

	// Require the expiration claim to be present.
	if doValidate && requireExp {
		jwtParseOptions = append(jwtParseOptions, jwt.WithRequiredClaim("exp"))
	}

	// Figure out the verification key.
	if doVerify {
		var parsedKey jwk.Key

		if viper.GetString(core.OptStr_JwtVerifyRsaKey) != "" {
			// Verify with RSA?
			logger.Debugw("using RSA key for JWT verification", "func", "crypto.getJwtParserOptions")
			rsaPublicKey := viper.GetString(core.OptStr_JwtVerifyRsaKey)
			parsedKey, err = jwk.ParseKey([]byte(rsaPublicKey), jwk.WithPEM(true))
			if err != nil {
				return jwtParseOptions, err
			}
			jwtParseOptions = append(jwtParseOptions, jwt.WithKey(jwa.RS256, parsedKey))

		} else if viper.GetString(core.OptStr_JwtVerifyHmacSecret) != "" {
			// Verify with HMAC?
			logger.Debugw("using HMAC secret for JWT verification", "func", "crypto.getJwtParserOptions")
			hmacSecret := viper.GetString(core.OptStr_JwtVerifyHmacSecret)
			key, err := jwk.ParseKey([]byte(hmacSecret))
			if err != nil {
				return jwtParseOptions, err
			}
			jwtParseOptions = append(jwtParseOptions, jwt.WithKey(jwa.HS256, key))

		} else if viper.GetString(core.OptStr_JwtVerifyJwksUrl) != "" {
			// Verify with JWKS URL?
			logger.Debugw("using JWKS URL for JWT verification", "func", "crypto.getJwtParserOptions")
			jwksUrl := viper.GetString(core.OptStr_JwtVerifyJwksUrl)
			cache := getJwksCache()
			if cache == nil {
				return nil, fmt.Errorf("failed to obtain cache instance: %w", err)
			}
			set, err := cache.Get(context.TODO(), jwksUrl)
			if err != nil {
				return nil, fmt.Errorf("failed to get JWKS from cache: %w", err)
			}
			logger.Debugw("obtained JWKS set from cache", "func", "crypto.getJwtParserOptions")
			jwtParseOptions = append(jwtParseOptions, jwt.WithKeySet(set))
		} else {
			// No key/alg to verify with.
			logger.Debugw("no key or algorithm defined for JWT verification", "func", "crypto.getJwtParserOptions")
			return jwtParseOptions, ErrJwtVerificationKeyNotSet
		}

	}

	return jwtParseOptions, nil
}

// Check a JWT by parsing, validating, and verifying.
//
// JWT parsing, validation, and verification are configurable.
func RunJwtChecks(tokenString string) (jwt.Token, error) {
	// Parse and verify the JWT.
	logger := core.GetLogger()
	var token jwt.Token

	doParse := viper.GetBool(core.OptStr_JwtParseEnabled)
	if doParse {
		jwtParserOptions, err := getJwtParserOptions()
		if err != nil {
			return nil, err
		}

		token, err = jwt.Parse([]byte(tokenString), jwtParserOptions...)
		if err != nil {
			logger.Errorw(
				"jwt parse failure",
				"func", "crypto.RunJwtChecks",
				"error", err.Error(),
			)
			return nil, err
		}
		logger.Debugw(
			"jwt parse success",
			"func", "crypto.RunJwtChecks",
			"token", token,
		)
	} else {
		logger.Debugw(
			"jwt parse disabled",
			"func", "crypto.RunJwtChecks",
			"token", token,
		)
	}
	return token, nil
}
