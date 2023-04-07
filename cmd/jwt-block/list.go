package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"divergent.codes/jwt-block/internal/blocklist"
	"divergent.codes/jwt-block/internal/cache"
	"divergent.codes/jwt-block/internal/core"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List blocked JWT hashes",
	Long:  "List all blocked JWT hashes in the blocklist",
	Run:   list,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func list(cmd *cobra.Command, args []string) {
	ShowBanner()

	redisDB := cache.GetRedisClient()
	result, _ := blocklist.List(redisDB)

	if viper.GetBool(core.OptStr_OutJSON) {
		json.NewEncoder(os.Stdout).Encode(result)
	} else {
		if len(result.TokenHashes) == 0 {
			fmt.Println("No token hashes in the blocklist")
		} else {
			for index, value := range result.TokenHashes {
				fmt.Printf("%d: %s\n", index, value)
			}
		}
	}
}
