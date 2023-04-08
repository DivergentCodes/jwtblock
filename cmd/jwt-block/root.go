/*
JWT Block is a blocklist & auth proxy service for JWTs, to support immediate termination of access, since access tokens cannot truly be revoked.

Usage:

	jwt-block [command]

Available Commands:

	block       Block a JWT
	check       Check if a JWT is blocked
	completion  Generate the autocompletion script for the specified shell
	flush       Empty the blocklist
	help        Help about any command
	list        List blocked JWT hashes
	serve       Serve the web API
	status      Get status of the blocklist
	unblock     Unblock a JWT
	version     Print the version of jwt-block

Flags:

	    --config string       config file (default is ./jwt-block.yaml)
	    --debug               Enable debug mode
	-h, --help                help for jwt-block
	    --json                Use JSON output
	-q, --quiet               Quiet CLI output
	    --redis-dbnum int     Redis DB number
	    --redis-host string   Redis host (default "localhost")
	    --redis-noverify      Skip Redis TLS certificate verification
	    --redis-pass string   Redis password
	    --redis-port int      Redis port (default 6379)
	    --redis-tls           Connect to Redis over TLS (default true)
	    --redis-user string   Redis username
	    --verbose             Verbose CLI output
*/
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
	var err error

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
	err = viper.BindPFlag(core.OptStr_Debug, rootCmd.PersistentFlags().Lookup("debug"))
	if err != nil {
		panic(err)
	}

	// json
	defaultOutJSON := viper.GetBool(core.OptStr_OutJSON)
	rootCmd.PersistentFlags().Bool("json", defaultOutJSON, "Use JSON output")
	err = viper.BindPFlag(core.OptStr_OutJSON, rootCmd.PersistentFlags().Lookup("json"))
	if err != nil {
		panic(err)
	}

	// quiet
	defaultQuiet := viper.GetBool(core.OptStr_Quiet)
	rootCmd.PersistentFlags().BoolP("quiet", "q", defaultQuiet, "Quiet CLI output")
	err = viper.BindPFlag(core.OptStr_Quiet, rootCmd.PersistentFlags().Lookup("quiet"))
	if err != nil {
		panic(err)
	}

	// verbose
	defaultVerbose := viper.GetBool(core.OptStr_Verbose)
	rootCmd.PersistentFlags().Bool("verbose", defaultVerbose, "Verbose CLI output")
	err = viper.BindPFlag(core.OptStr_Verbose, rootCmd.PersistentFlags().Lookup("verbose"))
	if err != nil {
		panic(err)
	}
}

func initRedisFlags() {
	var err error

	// redis.host
	defaultHost := viper.GetString(core.OptStr_RedisHost)
	rootCmd.PersistentFlags().String("redis-host", defaultHost, "Redis host")
	err = viper.BindPFlag(core.OptStr_RedisHost, rootCmd.PersistentFlags().Lookup("redis-host"))
	if err != nil {
		panic(err)
	}

	// redis.port
	defaultPort := viper.GetInt(core.OptStr_RedisPort)
	rootCmd.PersistentFlags().Int("redis-port", defaultPort, "Redis port")
	err = viper.BindPFlag(core.OptStr_RedisPort, rootCmd.PersistentFlags().Lookup("redis-port"))
	if err != nil {
		panic(err)
	}

	// redis.db_num
	defaultDbNum := viper.GetInt(core.OptStr_RedisDbnum)
	rootCmd.PersistentFlags().Int("redis-dbnum", defaultDbNum, "Redis DB number")
	err = viper.BindPFlag(core.OptStr_RedisDbnum, rootCmd.PersistentFlags().Lookup("redis-dbnum"))
	if err != nil {
		panic(err)
	}

	// redis.username
	defaultUser := viper.GetString(core.OptStr_RedisUsername)
	rootCmd.PersistentFlags().String("redis-user", defaultUser, "Redis username")
	err = viper.BindPFlag(core.OptStr_RedisUsername, rootCmd.PersistentFlags().Lookup("redis-user"))
	if err != nil {
		panic(err)
	}

	// redis.password
	defaultPassword := viper.GetString(core.OptStr_RedisPassword)
	rootCmd.PersistentFlags().String("redis-pass", defaultPassword, "Redis password")
	err = viper.BindPFlag(core.OptStr_RedisPassword, rootCmd.PersistentFlags().Lookup("redis-pass"))
	if err != nil {
		panic(err)
	}

	// redis.tls.enabled
	defaultTlsEnabled := viper.GetBool(core.OptStr_RedisTlsEnabled)
	rootCmd.PersistentFlags().Bool("redis-tls", defaultTlsEnabled, "Connect to Redis over TLS")
	err = viper.BindPFlag(core.OptStr_RedisTlsEnabled, rootCmd.PersistentFlags().Lookup("redis-tls"))
	if err != nil {
		panic(err)
	}

	// redis.tls.noverify
	defaultTlsNoverify := viper.GetBool(core.OptStr_RedisTlsNoverify)
	rootCmd.PersistentFlags().Bool("redis-noverify", defaultTlsNoverify, "Skip Redis TLS certificate verification")
	err = viper.BindPFlag(core.OptStr_RedisTlsNoverify, rootCmd.PersistentFlags().Lookup("redis-noverify"))
	if err != nil {
		panic(err)
	}
}

// Execute runs the root CLI command.
func Execute() error {
	return rootCmd.Execute()
}

// Display the CLI banner. Can be disabled with --quiet.
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
