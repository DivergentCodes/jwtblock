package crypto

import (
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"

	"divergent.codes/jwt-block/internal/core"
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

/*
var rsaPrivateKey string = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----`
*/

func Test_RunJwtChecks_NonJwt_NoParse_Success(t *testing.T) {
	viper.Set(core.OptStr_JwtParseEnabled, false)

	tokenString := "foobar"
	_, err := RunJwtChecks(tokenString)
	if err != nil {
		t.Errorf("JWT checks should have passed: err=%s", err)
	}
}

func Test_RunJwtChecks_ValidJwt_Parse_Success(t *testing.T) {
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, false)

	validTokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo0OTE2MjU5MDIyfQ.oNBGJ-XOzJZyXseUtsG1auKQnfQCdx50X8ymoA6eGKK3Gmc5GUYAIHr6vboK0Yll81xmrc-8BZUhMvv8lm-v2m-zsFFTU-SUVbB4G3gTaZITqr8Aic6a7ZZf5V8AemIUoCTd9fhmxaWjKJT67KhHNkHmfGmKS_44BnW0rvGHh6A3EuNLUyLol7bmDScY7mnSoRGXU5Hf-zeb885eK5-j28OBwqiJNhf1KNwuHyYQRSl_WZWORTmUNMG_chZ-jF6uZiF2hPAuEN2ZyEkZ6ZKIH4KklL9_cNVGGsklram-abnqzEtILtD4RtF-D_MUHTjRhVk_ZfD063kRlp49Zv4ZTg"
	_, err := RunJwtChecks(validTokenString)
	if err != nil {
		t.Errorf("JWT checks should have passed: err=%s", err)
	}
}

func Test_RunJwtChecks_NonJwt_Parse_Error(t *testing.T) {
	viper.Set(core.OptStr_JwtParseEnabled, true)

	tokenString := "foobar"
	_, err := RunJwtChecks(tokenString)
	if err == nil || err.Error() != "invalid JWT" {
		t.Errorf("JWT checks should have failed: err=%s", err)
	}
}

func Test_RunJwtChecks_ValidJwt_Validate_Success(t *testing.T) {
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)

	validTokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo0OTE2MjU5MDIyfQ.oNBGJ-XOzJZyXseUtsG1auKQnfQCdx50X8ymoA6eGKK3Gmc5GUYAIHr6vboK0Yll81xmrc-8BZUhMvv8lm-v2m-zsFFTU-SUVbB4G3gTaZITqr8Aic6a7ZZf5V8AemIUoCTd9fhmxaWjKJT67KhHNkHmfGmKS_44BnW0rvGHh6A3EuNLUyLol7bmDScY7mnSoRGXU5Hf-zeb885eK5-j28OBwqiJNhf1KNwuHyYQRSl_WZWORTmUNMG_chZ-jF6uZiF2hPAuEN2ZyEkZ6ZKIH4KklL9_cNVGGsklram-abnqzEtILtD4RtF-D_MUHTjRhVk_ZfD063kRlp49Zv4ZTg"
	_, err := RunJwtChecks(validTokenString)
	if err != nil {
		t.Errorf("JWT checks should have passed: err=%s", err)
	}
}

func Test_RunJwtChecks_ExpiredJwt_Validate_Error(t *testing.T) {
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)

	expiredTokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNjE2MjU5MDIyfQ.gGsWdwGk9tbKZKMZFFA3AdaVVLuTv-vXi3zrA4_cytJ2wPFk7Xo0ps6aJDoIIjjqzR0ZzKA1bReLG0YFhtMf-PNL5x9EzoA4269azT6RSg1RSRNkBcwq3PXEd0MCOi6AOUggO4yIxsQ2OhWOEB3SP2MVTpOQstzKioT84jnjE-DGOxPrRKZ1SWDCDyNG_K9svUF3NXjOTQNucMihYfT_H6uDx87sz0SPt7GpePjyvVTtVPuXq0RPIIwO_awnCHRMQ9tSu7TZ90_o7S1S3f784aYxufr6IuVKYZfOR1JaITJ5_QXNU0D6NukRzIgs_CmwLt1PCriWTtsR9Lgsoy2vkA"
	_, err := RunJwtChecks(expiredTokenString)
	if err == nil || err != jwt.ErrTokenExpired() {
		t.Errorf("Expected ErrTokenExpired: err=%s", err)
	}
}

func Test_RunJwtChecks_ValidRSAJwt_Verify_Success(t *testing.T) {
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, true)
	viper.Set(core.OptStr_JwtVerifyRsaKey, rsaPublicKey)

	validTokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo0OTE2MjU5MDIyfQ.oNBGJ-XOzJZyXseUtsG1auKQnfQCdx50X8ymoA6eGKK3Gmc5GUYAIHr6vboK0Yll81xmrc-8BZUhMvv8lm-v2m-zsFFTU-SUVbB4G3gTaZITqr8Aic6a7ZZf5V8AemIUoCTd9fhmxaWjKJT67KhHNkHmfGmKS_44BnW0rvGHh6A3EuNLUyLol7bmDScY7mnSoRGXU5Hf-zeb885eK5-j28OBwqiJNhf1KNwuHyYQRSl_WZWORTmUNMG_chZ-jF6uZiF2hPAuEN2ZyEkZ6ZKIH4KklL9_cNVGGsklram-abnqzEtILtD4RtF-D_MUHTjRhVk_ZfD063kRlp49Zv4ZTg"
	_, err := RunJwtChecks(validTokenString)
	if err != nil {
		t.Errorf("JWT checks should have passed: err=%s", err)
	}
}

func Test_RunJwtChecks_MissingRSAPublicKey_Verify_Error(t *testing.T) {
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, true)
	viper.Set(core.OptStr_JwtVerifyRsaKey, "")

	validTokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo0OTE2MjU5MDIyfQ.oNBGJ-XOzJZyXseUtsG1auKQnfQCdx50X8ymoA6eGKK3Gmc5GUYAIHr6vboK0Yll81xmrc-8BZUhMvv8lm-v2m-zsFFTU-SUVbB4G3gTaZITqr8Aic6a7ZZf5V8AemIUoCTd9fhmxaWjKJT67KhHNkHmfGmKS_44BnW0rvGHh6A3EuNLUyLol7bmDScY7mnSoRGXU5Hf-zeb885eK5-j28OBwqiJNhf1KNwuHyYQRSl_WZWORTmUNMG_chZ-jF6uZiF2hPAuEN2ZyEkZ6ZKIH4KklL9_cNVGGsklram-abnqzEtILtD4RtF-D_MUHTjRhVk_ZfD063kRlp49Zv4ZTg"
	_, err := RunJwtChecks(validTokenString)
	if err == nil || err != ErrJwtVerificationKeyNotSet {
		t.Errorf("Expected ErrTokenExpired: err=%s", err)
	}
}

func Test_RunJwtChecks_InvalidSignatureRSAJwt_Verify_Error(t *testing.T) {
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, true)
	viper.Set(core.OptStr_JwtVerifyRsaKey, rsaPublicKey)

	// Modified the signature.
	wrongSigTokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo0OTE2MjU5MDIyfQ.oNBGJ-XOzJZyXseUtsG1auKQnfQCdx50X8ymoA6eGKK3Gmc5GUYAIHr6vboK0Yll81xmrc-8BZUhMvv8lm-v2m-zsFFTU-SUVbB4G3gTaZITqr8Aic6a7ZZf5V8AemIUoCTd9fhmxaWjKJT67KhHNkHmfGmKS_44BnW0rvGHh6A3EuNLUyLol7bmDScY7mnSoRGXU5Hf-zeb885eK5-j28OBwqiJNhf1KNwuHyYQRSl_WZWORTmUNMG_chZ-jF6uZiF2hPAuEN2ZyEkZ6ZKIH4KklL9_cNVGGsklram-abnqzEtILtD4RtF-D_MUHTjRhVk_ZfD063kRlp49Zv"
	_, err := RunJwtChecks(wrongSigTokenString)
	if err == nil || err.Error() != "could not verify message using any of the signatures or keys" {
		t.Errorf("Expected ErrTokenExpired: err=%s", err)
	}
}

func Test_RunJwtChecks_InvalidSignatureBodyRSAJwt_Verify_Error(t *testing.T) {
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, true)
	viper.Set(core.OptStr_JwtVerifyRsaKey, rsaPublicKey)

	// Modified the body.
	wrongSigTokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjQ5MTYyNTkwMjJ9.oNBGJ-XOzJZyXseUtsG1auKQnfQCdx50X8ymoA6eGKK3Gmc5GUYAIHr6vboK0Yll81xmrc-8BZUhMvv8lm-v2m-zsFFTU-SUVbB4G3gTaZITqr8Aic6a7ZZf5V8AemIUoCTd9fhmxaWjKJT67KhHNkHmfGmKS_44BnW0rvGHh6A3EuNLUyLol7bmDScY7mnSoRGXU5Hf-zeb885eK5-j28OBwqiJNhf1KNwuHyYQRSl_WZWORTmUNMG_chZ-jF6uZiF2hPAuEN2ZyEkZ6ZKIH4KklL9_cNVGGsklram-abnqzEtILtD4RtF-D_MUHTjRhVk_ZfD063kRlp49Zv4ZTg"
	_, err := RunJwtChecks(wrongSigTokenString)
	if err == nil || err.Error() != "could not verify message using any of the signatures or keys" {
		t.Errorf("Expected ErrTokenExpired: err=%s", err)
	}
}

func Test_RunJwtChecks_ValidHMACJwt_Verify_Success(t *testing.T) {
	validTokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjQ5MTYyNTkwMjJ9.qhN3HXRpx439KiW5EridTfaTVNDvB6_b4LKLgAWgLDY"
	hmacSecret := "foobar"

	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, false)
	viper.Set(core.OptStr_JwtVerifyHmacSecret, hmacSecret)

	_, err := RunJwtChecks(validTokenString)
	if err != nil {
		t.Errorf("JWT checks should have passed: err=%s", err)
	}
}

func Test_RunJwtChecks_ActiveTokenWithExp_RequireExp_Success(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoic29tZS1hdWRpZW5jZSIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6OTUxNjI0OTAyMn0.-sPRLbGm8U9aYNlrH1XAnVFF2qyQ_0h-4pKPeIXMnQE"

	// Set the config.
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, false)

	// Require the EXP claim.
	viper.Set(core.OptStr_JwtTTLRequireTokenExp, true)

	// Run.
	_, err := RunJwtChecks(tokenString)

	// Check.
	if err != nil {
		t.Errorf("JWT checks should have passed: err=%s", err)
	}
}

func Test_RunJwtChecks_TokenWithoutExp_NoRequireExp_Success(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoic29tZS1hdWRpZW5jZSIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.rl2J3nyAGTmKY5AyzDuRndyEa_dWm5fzgyEYxz3pp-0"

	// Set the config.
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, false)

	// Do not require the EXP claim.
	viper.Set(core.OptStr_JwtTTLRequireTokenExp, false)

	// Run.
	_, err := RunJwtChecks(tokenString)

	// Check.
	if err != nil {
		t.Errorf("JWT checks should have passed: err=%s", err)
	}
}

func Test_RunJwtChecks_TokenWithoutExp_RequireExp_Error(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoic29tZS1hdWRpZW5jZSIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.rl2J3nyAGTmKY5AyzDuRndyEa_dWm5fzgyEYxz3pp-0"

	// Set the config.
	viper.Set(core.OptStr_JwtParseEnabled, true)
	viper.Set(core.OptStr_JwtValidateEnabled, true)
	viper.Set(core.OptStr_JwtVerifyEnabled, false)

	// Require the EXP claim.
	viper.Set(core.OptStr_JwtTTLRequireTokenExp, true)

	// Run.
	_, err := RunJwtChecks(tokenString)

	// Check.
	if err == nil || !errors.Is(err, jwt.ErrMissingRequiredClaim("exp")) {
		t.Errorf("Found Expected error: err=%s", err)
	}
}
