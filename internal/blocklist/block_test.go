package blocklist

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"

	"github.com/divergentcodes/jwt-block/internal/core"
	"github.com/divergentcodes/jwt-block/internal/crypto"
)

var rsaPublicKey string = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`

func Test_BlockWithTTL_ValidToken_OnlyParse_Success(t *testing.T) {
	var err error

	// Values.
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
	ttlSeconds := 60

	// Set the config.
	core.InitConfigDefaults()
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, false)
	viper.Set(core.OptStr_JwtVerifyEnabled, false)

	// Setup mock cache.
	ttl := time.Duration(ttlSeconds) * time.Second
	cacheKey := crypto.Sha256FromString(tokenString)
	redisDB, redisMock := redismock.NewClientMock()

	// Add the token and check.
	redisMock.ExpectSetNX(cacheKey, true, ttl).SetVal(true)
	_, err = BlockWithTTL(redisDB, tokenString, ttlSeconds)
	if err != nil {
		t.Errorf("Adding token to blocklist failed: err=%s", err)
	}

	// Add the token again, which isn't set when it already exists.
	redisMock.ExpectSetNX(cacheKey, true, ttl).SetVal(false)
	_, err = BlockWithTTL(redisDB, tokenString, ttlSeconds)
	if err != nil {
		t.Errorf("Re-adding token to blocklist failed: err=%s", err)
	}

	// Verify all expected Redis commands and results happened.
	if err = redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func Test_BlockWithTTL_ValidToken_NoVerify_Success(t *testing.T) {
	var err error

	// Values.
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoic29tZS1hdWRpZW5jZSIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.fw4UBPdz0MioRQKM7G0VvMZEHMkfws_416zns2_qsMu_tTJtLHQH_Savib2-_2G1ze8nJKL7n7clACUxcVsyriJuu0Ww7ZX8cXb2WQnrzPUFOFsTlcwqplY7RkZhwmRcu4U_5RLJmwY6oq9-A689YN8oD8oD35GTgx5LrBsMax7YKTjk0f2X1-Qd7QMZyXUyTRrCEUTEqOklQ0DoemlpcXYTBdqae8G9iufEvKMu6SUiRrFM9hgz11zmeEFMrhJ30UUPMnqcqRFIXNGNFaPUt26LYKKNRDjPkKo4ErXI7TknuSj9zyGTm4u_jWsALb-4pa3HSLwjqavKSQflEupZ5w"
	ttlSeconds := 60

	// Set the config.
	core.InitConfigDefaults()
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, false)

	// Setup mock cache.
	ttl := time.Duration(ttlSeconds) * time.Second
	cacheKey := crypto.Sha256FromString(tokenString)
	redisDB, redisMock := redismock.NewClientMock()

	// Add the token and check.
	redisMock.ExpectSetNX(cacheKey, true, ttl).SetVal(true)
	_, err = BlockWithTTL(redisDB, tokenString, ttlSeconds)
	if err != nil {
		t.Errorf("Adding token to blocklist failed: err=%s", err)
	}

	// Add the token again, which isn't set when it already exists.
	redisMock.ExpectSetNX(cacheKey, true, ttl).SetVal(false)
	_, err = BlockWithTTL(redisDB, tokenString, ttlSeconds)
	if err != nil {
		t.Errorf("Re-adding token to blocklist failed: err=%s", err)
	}

	// Verify all expected Redis commands and results happened.
	if err = redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func Test_BlockWithTTL_ValidToken_FullVerify_MissingKey_Error(t *testing.T) {
	var err error

	// Values.
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoic29tZS1hdWRpZW5jZSIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.fw4UBPdz0MioRQKM7G0VvMZEHMkfws_416zns2_qsMu_tTJtLHQH_Savib2-_2G1ze8nJKL7n7clACUxcVsyriJuu0Ww7ZX8cXb2WQnrzPUFOFsTlcwqplY7RkZhwmRcu4U_5RLJmwY6oq9-A689YN8oD8oD35GTgx5LrBsMax7YKTjk0f2X1-Qd7QMZyXUyTRrCEUTEqOklQ0DoemlpcXYTBdqae8G9iufEvKMu6SUiRrFM9hgz11zmeEFMrhJ30UUPMnqcqRFIXNGNFaPUt26LYKKNRDjPkKo4ErXI7TknuSj9zyGTm4u_jWsALb-4pa3HSLwjqavKSQflEupZ5w"
	ttlSeconds := 60

	// Set the config.
	core.InitConfigDefaults()
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, true)

	// Setup mock cache.
	redisDB, redisMock := redismock.NewClientMock()

	// Add the token and check.
	_, err = BlockWithTTL(redisDB, tokenString, ttlSeconds)
	if err == nil || err != crypto.ErrJwtVerificationKeyNotSet {
		t.Errorf("Expected 'Missing RSA public key' error: err=%s", err)
	}

	// Verify all expected Redis commands and results happened.
	if err = redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func Test_BlockWithTTL_ValidToken_FullVerify_Success(t *testing.T) {
	var err error

	// Values.
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoic29tZS1hdWRpZW5jZSIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.fw4UBPdz0MioRQKM7G0VvMZEHMkfws_416zns2_qsMu_tTJtLHQH_Savib2-_2G1ze8nJKL7n7clACUxcVsyriJuu0Ww7ZX8cXb2WQnrzPUFOFsTlcwqplY7RkZhwmRcu4U_5RLJmwY6oq9-A689YN8oD8oD35GTgx5LrBsMax7YKTjk0f2X1-Qd7QMZyXUyTRrCEUTEqOklQ0DoemlpcXYTBdqae8G9iufEvKMu6SUiRrFM9hgz11zmeEFMrhJ30UUPMnqcqRFIXNGNFaPUt26LYKKNRDjPkKo4ErXI7TknuSj9zyGTm4u_jWsALb-4pa3HSLwjqavKSQflEupZ5w"
	ttlSeconds := 60

	// Set the config.
	core.InitConfigDefaults()
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, true)
	viper.Set(core.OptStr_JwtVerifyRsaKey, rsaPublicKey)

	// Setup mock cache.
	redisDB, redisMock := redismock.NewClientMock()
	ttl := time.Duration(ttlSeconds) * time.Second
	cacheKey := crypto.Sha256FromString(tokenString)

	// Add the token and check.
	redisMock.ExpectSetNX(cacheKey, true, ttl).SetVal(true)
	_, err = BlockWithTTL(redisDB, tokenString, ttlSeconds)
	if err != nil {
		t.Errorf("Adding token to blocklist failed: err=%s", err)
	}

	// Add the token again, which isn't set when it already exists.
	redisMock.ExpectSetNX(cacheKey, true, ttl).SetVal(false)
	_, err = BlockWithTTL(redisDB, tokenString, ttlSeconds)
	if err != nil {
		t.Errorf("Re-adding token to blocklist failed: err=%s", err)
	}

	// Verify all expected Redis commands and results happened.
	if err = redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func Test_Block_TTLFromExp_CorrectTTL_Success(t *testing.T) {

	// Setup to use TTL from EXP, but don't verify signature.
	core.InitConfigDefaults()
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, false)
	viper.Set(core.OptStr_JwtTTLUseTokenExp, true)
	viper.Set(core.OptStr_JwtTTLDefaultSeconds, 7200) // 2 hours
	viper.Set(core.OptStr_JwtTTLExpPaddingSeconds, 0)
	ttlExpected := 1800 // 30 minutes
	tokenString := generateTokenStringHS256(ttlExpected)
	redisDB, _ := redismock.NewClientMock()

	// Add the token and check.
	_, err := Block(redisDB, tokenString)

	// Parse the clock skewed TTL out of the Redis Mock error.
	re := regexp.MustCompile(` [0-9]+ `)
	ttlParsed := re.FindString(err.Error())
	ttlParsed = strings.TrimSpace(ttlParsed)
	ttlActual, _ := strconv.Atoi(ttlParsed)

	// Check the TTL difference, accounting for clock skew.
	ttlDelta := int(math.Abs(float64(ttlActual) - float64(ttlExpected)))
	maxDelta := 3
	if ttlDelta > maxDelta {
		t.Errorf(
			"TTL is more than %d seconds off expected: actual=%d, expected=%d",
			maxDelta,
			ttlActual,
			ttlExpected,
		)
	}
}

func Test_Block_TTLFromExpWithPadding_CorrectTTL_Success(t *testing.T) {

	// Setup to use TTL from EXP, but don't verify signature.
	core.InitConfigDefaults()
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, false)
	viper.Set(core.OptStr_JwtTTLUseTokenExp, true)
	viper.Set(core.OptStr_JwtTTLDefaultSeconds, 7200) // 2 hours
	ttl := 1800                                       // 30 minutes
	tokenString := generateTokenStringHS256(ttl)

	ttlPadding := 85
	viper.Set(core.OptStr_JwtTTLExpPaddingSeconds, ttlPadding)

	ttlExpected := ttl + ttlPadding
	redisDB, _ := redismock.NewClientMock()

	// Add the token and check.
	_, err := Block(redisDB, tokenString)

	// Parse the clock skewed TTL out of the Redis Mock error.
	re := regexp.MustCompile(` [0-9]+ `)
	ttlParsed := re.FindString(err.Error())
	ttlParsed = strings.TrimSpace(ttlParsed)
	ttlActual, _ := strconv.Atoi(ttlParsed)

	// Check the TTL difference, accounting for clock skew.
	ttlDelta := int(math.Abs(float64(ttlActual) - float64(ttlExpected)))
	maxDelta := 3
	if ttlDelta > maxDelta {
		t.Errorf(
			"TTL is more than %d seconds off expected: actual=%d, expected=%d",
			maxDelta,
			ttlActual,
			ttlExpected,
		)
	}
}

func Test_calculateTokenTTL_2Hour_Success(t *testing.T) {
	ttlExpected := 7200
	core.InitConfigDefaults()
	viper.Set(core.OptStr_JwtTTLExpPaddingSeconds, 0)

	// Generate the token.
	tokenString := generateTokenStringHS256(ttlExpected)
	token, _ := crypto.RunJwtChecks(tokenString)

	// Calculate TTL.
	ttlActual, err := calculateTokenTTLFromExp(token)
	if err != nil {
		t.Errorf("Expected no error: ttl=%d, err=%s", ttlActual, err)
	}

	// Check, accounting for time lag.
	ttlDelta := int(math.Abs(float64(ttlExpected) - float64(ttlActual)))
	maxDelta := 3
	if ttlDelta > maxDelta {
		t.Errorf(
			"TTL is more than %d seconds off expected: actual=%d, expected=%d",
			ttlDelta,
			ttlExpected,
			ttlActual,
		)
	}
}

func Test_calculateTokenTTL_NoExp(t *testing.T) {
	tokenString := generateTokenStringHS256(-1)
	token, _ := crypto.RunJwtChecks(tokenString)

	// Set the config.
	core.InitConfigDefaults()
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, false)

	ttl, err := calculateTokenTTLFromExp(token)
	if ttl != -1 || !errors.Is(err, ErrNoExpForTTL) {
		t.Errorf(
			"Expected error 'Token has no set expiration' with TTL of -1: ttl=%d, err=%s",
			ttl,
			err,
		)
	}
}

func generateTokenStringHS256(ttlSeconds int) string {
	// Generate the token headers.
	tokenHeaders := jws.NewHeaders()
	tokenHeaders.Set("typ", "JWT")

	// Generate the token body, with the given EXP claim.
	var tokenBody jwt.Token
	if ttlSeconds >= 0 {
		ttl := time.Duration(ttlSeconds) * time.Second
		expiration := time.Now().Add(ttl)
		tokenBody, _ = jwt.NewBuilder().
			Issuer(`some-issuer`).
			Expiration(expiration).
			Build()
	} else {
		tokenBody, _ = jwt.NewBuilder().
			Issuer(`some-issuer`).
			Build()
	}
	tokenBodyBytes, _ := jwt.NewSerializer().Serialize(tokenBody)

	// Generate the signed, finished HS256 token.
	key, _ := jwk.FromRaw([]byte(`foobar`))
	tokenBytes, _ := jws.Sign(
		tokenBodyBytes,
		jws.WithKey(jwa.HS256, key, jws.WithProtectedHeaders(tokenHeaders)),
	)
	tokenString := string(tokenBytes)
	return tokenString
}
