package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"divergent.codes/jwt-block/internal/core"
)

var (
	rootCmd = &cobra.Command{
		Use:   "jwt-block",
		Short: "A JWT blocklist & auth proxy service",
		Long:  `JWT Block is a blocklist & auth proxy service for JWTs, to support immediate termination of access, since access tokens cannot truly be revoked.`,
	}
)

// Run for root command. Will execute for all subcommands.
func init() {
	initRootFlags()
	initRedisFlags()
}

func initRootFlags() {

	// config
	var cfgFile string
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./jwt-block.yaml)")
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	}

	// debug
	defaultDebug := viper.GetBool(core.OptStr_Debug)
	rootCmd.PersistentFlags().Bool("debug", defaultDebug, "Enable debug mode")
	viper.BindPFlag(core.OptStr_Debug, rootCmd.PersistentFlags().Lookup("debug"))

	// json
	defaultOutJSON := viper.GetBool(core.OptStr_OutJSON)
	rootCmd.PersistentFlags().Bool("json", defaultOutJSON, "Use JSON output")
	viper.BindPFlag(core.OptStr_OutJSON, rootCmd.PersistentFlags().Lookup("json"))

	// quiet
	defaultQuiet := viper.GetBool(core.OptStr_Quiet)
	rootCmd.PersistentFlags().BoolP("quiet", "q", defaultQuiet, "Quiet CLI output")
	viper.BindPFlag(core.OptStr_Quiet, rootCmd.PersistentFlags().Lookup("quiet"))

	// verbose
	defaultVerbose := viper.GetBool(core.OptStr_Verbose)
	rootCmd.PersistentFlags().Bool("verbose", defaultVerbose, "Verbose CLI output")
	viper.BindPFlag(core.OptStr_Verbose, rootCmd.PersistentFlags().Lookup("verbose"))
}

func initRedisFlags() {
	// redis.host
	defaultHost := viper.GetString(core.OptStr_RedisHost)
	rootCmd.PersistentFlags().String("redis-host", defaultHost, "Redis host")
	viper.BindPFlag(core.OptStr_RedisHost, rootCmd.PersistentFlags().Lookup("redis-host"))

	// redis.port
	defaultPort := viper.GetInt(core.OptStr_RedisPort)
	rootCmd.PersistentFlags().Int("redis-port", defaultPort, "Redis port")
	viper.BindPFlag(core.OptStr_RedisPort, rootCmd.PersistentFlags().Lookup("redis-port"))

	// redis.db_num
	defaultDbNum := viper.GetInt(core.OptStr_RedisDbnum)
	rootCmd.PersistentFlags().Int("redis-dbnum", defaultDbNum, "Redis DB number")
	viper.BindPFlag(core.OptStr_RedisDbnum, rootCmd.PersistentFlags().Lookup("redis-dbnum"))

	// redis.username
	defaultUser := viper.GetString(core.OptStr_RedisUsername)
	rootCmd.PersistentFlags().String("redis-user", defaultUser, "Redis username")
	viper.BindPFlag(core.OptStr_RedisUsername, rootCmd.PersistentFlags().Lookup("redis-user"))

	// redis.password
	defaultPassword := viper.GetString(core.OptStr_RedisPassword)
	rootCmd.PersistentFlags().String("redis-pass", defaultPassword, "Redis password")
	viper.BindPFlag(core.OptStr_RedisPassword, rootCmd.PersistentFlags().Lookup("redis-pass"))

	// redis.tls.enabled
	defaultTlsEnabled := viper.GetBool(core.OptStr_RedisTlsEnabled)
	rootCmd.PersistentFlags().Bool("redis-tls", defaultTlsEnabled, "Connect to Redis over TLS")
	viper.BindPFlag(core.OptStr_RedisTlsEnabled, rootCmd.PersistentFlags().Lookup("redis-tls"))

	// redis.tls.noverify
	defaultTlsNoverify := viper.GetBool(core.OptStr_RedisTlsNoverify)
	rootCmd.PersistentFlags().Bool("redis-noverify", defaultTlsNoverify, "Skip Redis TLS certificate verification")
	viper.BindPFlag(core.OptStr_RedisTlsNoverify, rootCmd.PersistentFlags().Lookup("redis-noverify"))
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func ShowBanner() {
	quiet := viper.GetBool("quiet")
	outJSON := viper.GetBool(core.OptStr_OutJSON)

	if !quiet && !outJSON {
		fmt.Printf("JWT Block %s created by %s <%s>\n", core.Version, core.AuthorName, core.AuthorEmail)
		if viper.GetBool(core.OptStr_Debug) {
			fmt.Println("DEBUG mode is enabled")
		}
		fmt.Println("")
	}
}
