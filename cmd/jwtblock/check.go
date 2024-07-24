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
	checkUseSha256 bool

	checkCmd = &cobra.Command{
		Use:   "check [<JWT>] [--sha256 <HASH>]",
		Short: "Check if a JWT is blocked",
		Long:  "Check if a JWT is blocked",
		Args:  cobra.ExactArgs(1),
		Run:   check,
	}
)

func init() {
	checkCmd.Flags().BoolVar(&checkUseSha256, "sha256", false, "Check by SHA256 of token instead")

	rootCmd.AddCommand(checkCmd)
}

func check(cmd *cobra.Command, args []string) {
	ShowBanner()
	redisDB := cache.GetRedisClient()

	var checkResult blocklist.CheckResult
	var err error
	value := args[0]

	// Hash or token.
	if checkUseSha256 {
		checkResult, err = blocklist.CheckBySha256(redisDB, value)
	} else {
		checkResult, err = blocklist.CheckByJwt(redisDB, value)
	}

	// Error handling.
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
		return
	}

	// Show output.
	if viper.GetBool(core.OptStr_OutJSON) {
		checkJSON, _ := json.Marshal(checkResult)

		fmt.Println(string(checkJSON))
	} else {
		if checkResult.IsBlocked {
			fmt.Println("Token is blocked")
		} else {
			fmt.Println("Token is allowed")
		}
	}

}
