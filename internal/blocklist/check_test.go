package blocklist

import (
	"errors"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/spf13/viper"

	"divergent.codes/jwt-block/internal/core"
	"divergent.codes/jwt-block/internal/crypto"
)

func Test_CheckByJwt_ValidToken_ExistsFound_Success(t *testing.T) {
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
	ttlSeconds := 60

	// Setup mock cache, with the token in place.
	ttl := time.Duration(ttlSeconds) * time.Second
	cacheKey := crypto.Sha256FromString(tokenString)
	redisDB, redisMock := redismock.NewClientMock()
	redisDB.SetNX(redisContext, cacheKey, true, ttl)

	// Lookup the existing token.
	redisMock.ExpectTTL(cacheKey).RedisNil()
	_, err := CheckByJwt(redisDB, tokenString)
	if err != nil {
		t.Errorf("Token check failed: err=%s", err)
	}

	// Verify all expected Redis commands and results happened.
	if err = redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func Test_CheckByJwt_ValidToken_NotExistsNotFound_Success(t *testing.T) {
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"

	// Setup mock cache.
	cacheKey := crypto.Sha256FromString(tokenString)
	redisDB, redisMock := redismock.NewClientMock()

	// Lookup the token that isn't there.
	redisMock.ExpectTTL(cacheKey).RedisNil()
	_, err := CheckByJwt(redisDB, tokenString)
	if err != nil {
		t.Errorf("Token check failed: err=%s", err)
	}

	// Verify all expected Redis commands and results happened.
	if err = redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func Test_CheckBySha256_ValidHash_ExistsFound_Success(t *testing.T) {
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
	tokenHash := crypto.Sha256FromString(tokenString)
	ttlSeconds := 60

	// Setup mock cache, with the token in place.
	ttl := time.Duration(ttlSeconds) * time.Second
	redisDB, redisMock := redismock.NewClientMock()
	redisDB.SetNX(redisContext, tokenHash, true, ttl)

	// Lookup the existing token.
	redisMock.ExpectTTL(tokenHash).RedisNil()
	_, err := CheckBySha256(redisDB, tokenHash)
	if err != nil {
		t.Errorf("Token check failed: err=%s", err)
	}

	// Verify all expected Redis commands and results happened.
	if err = redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func Test_CheckBySha256_InvalidHash_Error(t *testing.T) {
	tokenHash := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	ttlSeconds := 60

	// Setup mock cache, with the token in place.
	ttl := time.Duration(ttlSeconds) * time.Second
	redisDB, redisMock := redismock.NewClientMock()
	redisDB.SetNX(redisContext, tokenHash, true, ttl)

	// Lookup the existing token.
	_, err := CheckBySha256(redisDB, tokenHash)
	if err == nil || !errors.Is(err, crypto.ErrMalformedSha256) {
		t.Errorf("Expected error ErrMalformedSha256: err=%s", err)
	}

	// Verify all expected Redis commands and results happened.
	if err = redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func Test_CheckByJwt_InvalidToken_BadSignature_Error(t *testing.T) {
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942Xhe"
	ttlSeconds := 60

	// Set the config.
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, true)
	viper.Set(core.OptStr_JwtVerifyRsaKey, rsaPublicKey)

	// Setup mock cache, with the token in place.
	ttl := time.Duration(ttlSeconds) * time.Second
	cacheKey := crypto.Sha256FromString(tokenString)
	redisDB, redisMock := redismock.NewClientMock()
	redisDB.SetNX(redisContext, cacheKey, true, ttl)

	// Lookup the existing token.
	_, err := CheckByJwt(redisDB, tokenString)
	if err == nil || err.Error() != "could not verify message using any of the signatures or keys" {
		t.Errorf("Expected error 'could not verify message using any of the signatures or keys': err=%s", err)
	}

	// Verify all expected Redis commands and results happened.
	if err = redisMock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}
