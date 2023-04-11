package core

import (
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Initialize the application configuration settings and defaults.
func InitConfigDefaults() {
	initRootDefaults()
	initBlocklistDefaults()
	initRedisDefaults()
	initHttpDefaults()

	initConfigFile()
	initConfigEnv()
}

// Root configuration options
var (
	OptStr_Debug   = "debug"
	OptStr_OutJSON = "out-json"
	OptStr_Quiet   = "quiet"
	OptStr_Verbose = "verbose"
)

func initRootDefaults() {
	viper.SetDefault(OptStr_Debug, false)
	viper.SetDefault(OptStr_OutJSON, false)
	viper.SetDefault(OptStr_Quiet, false)
	viper.SetDefault(OptStr_Verbose, false)
}

// Blocklist configuration options
var (
	OptStr_JwtParseEnabled    = "jwt.parse.enabled"
	OptStr_JwtValidateEnabled = "jwt.validate.enabled"

	OptStr_JwtVerifyEnabled    = "jwt.verify.enabled"
	OptStr_JwtVerifyRsaKey     = "jwt.verify.rsa_key"
	OptStr_JwtVerifyHmacSecret = "jwt.verify.hmac_secret"

	OptStr_JwtTTLDefaultSeconds    = "jwt.ttl.sec_default"
	OptStr_JwtTTLSpecifiedSeconds  = "jwt.ttl.sec_specified"
	OptStr_JwtTTLExpPaddingSeconds = "jwt.ttl.sec_padding"
	OptStr_JwtTTLUseTokenExp       = "jwt.ttl.use_token_exp"
	OptStr_JwtTTLRequireTokenExp   = "jwt.ttl.require_token_exp"
)

func initBlocklistDefaults() {
	viper.SetDefault(OptStr_JwtParseEnabled, true)
	viper.SetDefault(OptStr_JwtValidateEnabled, true)

	viper.SetDefault(OptStr_JwtVerifyEnabled, false)
	viper.SetDefault(OptStr_JwtVerifyRsaKey, "")
	viper.SetDefault(OptStr_JwtVerifyHmacSecret, "")

	viper.SetDefault(OptStr_JwtTTLDefaultSeconds, 7200) // 2 hours
	viper.SetDefault(OptStr_JwtTTLSpecifiedSeconds, -1)
	viper.SetDefault(OptStr_JwtTTLExpPaddingSeconds, 5)
	viper.SetDefault(OptStr_JwtTTLUseTokenExp, true)
	viper.SetDefault(OptStr_JwtTTLRequireTokenExp, false)
}

// Redis configuration options
var (
	OptStr_RedisHost        = "redis.host"
	OptStr_RedisPort        = "redis.port"
	OptStr_RedisDbnum       = "redis.dbnum"
	OptStr_RedisUsername    = "redis.username"
	OptStr_RedisPassword    = "redis.password"
	OptStr_RedisTlsEnabled  = "redis.tls.enabled"
	OptStr_RedisTlsNoverify = "redis.tls.noverify"
)

func initRedisDefaults() {
	viper.SetDefault(OptStr_RedisHost, "localhost")
	viper.SetDefault(OptStr_RedisPort, 6379)
	viper.SetDefault(OptStr_RedisDbnum, 0)
	viper.SetDefault(OptStr_RedisUsername, "")
	viper.SetDefault(OptStr_RedisPassword, "")
	viper.SetDefault(OptStr_RedisTlsEnabled, false)
	viper.SetDefault(OptStr_RedisTlsNoverify, false)
}

// HTTP service configuration options
var (
	OptStr_HttpHostname        = "http.hostname"
	OptStr_HttpPort            = "http.port"
	OptStr_HttpHeaderSha256    = "http.http_header_sha256"
	OptStr_HttpStatusOnAllowed = "http.status_on_allowed"
	OptStr_HttpStatusOnBlocked = "http.status_on_blocked"
)

func initHttpDefaults() {
	viper.SetDefault(OptStr_HttpHostname, "")
	viper.SetDefault(OptStr_HttpPort, 4474)
	viper.SetDefault(OptStr_HttpHeaderSha256, "x-jwtblock-sha256")
	viper.SetDefault(OptStr_HttpStatusOnAllowed, 200)
	viper.SetDefault(OptStr_HttpStatusOnBlocked, 401)
}

func initConfigFile() {

	// Use default config file location.
	viper.AddConfigPath(".")
	viper.SetConfigName(".jwt-block")
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found. Ignore error and continue.
		} else {
			// Config file was found but another error was produced.
			os.Exit(1)
		}
	}

}

func initConfigEnv() {
	// Support equivalent environment variables.
	viper.SetEnvPrefix("JWTBLOCK")
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.AutomaticEnv()
}
