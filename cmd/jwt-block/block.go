package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/divergentcodes/jwt-block/internal/blocklist"
	"github.com/divergentcodes/jwt-block/internal/cache"
	"github.com/divergentcodes/jwt-block/internal/core"
)

var (
	blockCmd = &cobra.Command{
		Use:   "block <JWT>",
		Short: "Block a JWT",
		Long:  `Block a JWT by adding it to the blocklist`,
		Args:  cobra.ExactArgs(1),
		Run:   block,
	}
)

func init() {

	// jwt.ttl.sec_specified
	specifiedTTL := viper.GetInt(core.OptStr_JwtTTLSpecifiedSeconds)
	blockCmd.Flags().IntP("ttl", "t", specifiedTTL, "TTL for token blocking in seconds")
	err := viper.BindPFlag(core.OptStr_JwtTTLSpecifiedSeconds, blockCmd.Flags().Lookup("ttl"))
	if err != nil {
		panic(err)
	}

	rootCmd.AddCommand(blockCmd)
}

func block(cmd *cobra.Command, args []string) {
	ShowBanner()

	tokenString := args[0]
	var result *blocklist.BlockResult
	var err error
	redisDB := cache.GetRedisClient()

	// Add to blocklist.
	ttl := viper.GetInt(core.OptStr_JwtTTLSpecifiedSeconds)
	if ttl < 0 {
		result, err = blocklist.Block(redisDB, tokenString)
	} else {
		result, err = blocklist.BlockWithTTL(redisDB, tokenString, ttl)
	}
	if err != nil {
		fmt.Printf("Failed to add token to blocklist: err=%s\n", err.Error())
		return
	}

	// Output.
	if viper.GetBool(core.OptStr_OutJSON) {
		blockJSON, _ := json.Marshal(result)
		fmt.Println(string(blockJSON))
	} else {
		msg := blocklist.SuccessTokenBlocked
		if !result.IsNew {
			msg = blocklist.SuccessTokenExists
		}
		fmt.Printf("%s [New: %t] [TTL: %s]\n", msg, result.IsNew, result.TTLString)
	}
}
