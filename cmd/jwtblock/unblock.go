package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/divergentcodes/jwtblock/internal/blocklist"
	"github.com/divergentcodes/jwtblock/internal/cache"
	"github.com/divergentcodes/jwtblock/internal/core"
)

var (
	// Used for flags.
	unblockUseSha256 bool

	unblockCmd = &cobra.Command{
		Use:   "unblock [<JWT>] [--sha256 <HASH>]",
		Short: "Unblock a JWT",
		Long:  "Unblock a JWT by deleting it from the blocklist",
		Args:  cobra.ExactArgs(1),
		Run:   unblock,
	}
)

func init() {
	unblockCmd.Flags().BoolVar(&unblockUseSha256, "sha256", false, "Unblock by SHA256 of token instead")

	rootCmd.AddCommand(unblockCmd)
}

func unblock(cmd *cobra.Command, args []string) {
	ShowBanner()
	redisDB := cache.GetRedisClient()

	var result *blocklist.UnblockResult
	var err error
	value := args[0]

	// Hash or token.
	if unblockUseSha256 {
		result, err = blocklist.UnblockBySha256(redisDB, value)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			return
		}
	} else {
		result, err = blocklist.UnblockByJwt(redisDB, value)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			return
		}
	}

	// Show output.
	if viper.GetBool(core.OptStr_OutJSON) {
		unblockJSON, _ := json.Marshal(result)
		fmt.Println(string(unblockJSON))
	} else {
		fmt.Println(result.Message)
	}
}
