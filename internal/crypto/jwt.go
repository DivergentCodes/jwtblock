package crypto

import (
	"errors"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"

	"divergent.codes/jwt-block/internal/core"
)

var (
	ErrJwtVerificationKeyNotSet = errors.New("No key set for JWT verification")
)

func getJwtParserOptions() ([]jwt.ParseOption, error) {
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
			rsaPublicKey := viper.GetString(core.OptStr_JwtVerifyRsaKey)
			parsedKey, err = jwk.ParseKey([]byte(rsaPublicKey), jwk.WithPEM(true))
			if err != nil {
				return jwtParseOptions, err
			}
			jwtParseOptions = append(jwtParseOptions, jwt.WithKey(jwa.RS256, parsedKey))

		} else if viper.GetString(core.OptStr_JwtVerifyHmacSecret) != "" {
			// Verify with HMAC?
			hmacSecret := viper.GetString(core.OptStr_JwtVerifyHmacSecret)
			key, err := jwk.ParseKey([]byte(hmacSecret))
			if err != nil {
				return jwtParseOptions, err
			}
			jwtParseOptions = append(jwtParseOptions, jwt.WithKey(jwa.HS256, key))

		} else {
			// No key/alg to verify with.
			return jwtParseOptions, ErrJwtVerificationKeyNotSet
		}

	}

	return jwtParseOptions, nil
}

func RunJwtChecks(tokenString string) (jwt.Token, error) {
	// Parse and verify the JWT.
	logger := core.GetLogger()
	var token jwt.Token

	logger.Debugw(
		"JWT parsing config",
		core.OptStr_JwtParseEnabled, viper.GetBool(core.OptStr_JwtParseEnabled),
		core.OptStr_JwtValidateEnabled, viper.GetBool(core.OptStr_JwtValidateEnabled),
		core.OptStr_JwtVerifyEnabled, viper.GetBool(core.OptStr_JwtVerifyEnabled),
	)

	doParse := viper.GetBool(core.OptStr_JwtParseEnabled)
	if doParse {
		jwtParserOptions, err := getJwtParserOptions()
		if err != nil {
			return nil, err
		}

		token, err = jwt.Parse([]byte(tokenString), jwtParserOptions...)
		if err != nil {
			logger.Errorw("Failed to parse token", "error", err.Error())
			return nil, err
		}
	}
	return token, nil
}
