package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"divergent.codes/jwt-block/internal/blocklist"
	"divergent.codes/jwt-block/internal/cache"
	"divergent.codes/jwt-block/internal/core"
)

var flushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Empty the blocklist",
	Long:  "Empty the blocklist",
	Run:   flush,
}

func init() {
	rootCmd.AddCommand(flushCmd)
}

func flush(cmd *cobra.Command, args []string) {
	ShowBanner()

	redisDB := cache.GetRedisClient()

	result, err := blocklist.Flush(redisDB)
	if err != nil {
		fmt.Printf("Error flushing the blocklist: %s", err.Error())
		return
	}

	// Show output.
	if viper.GetBool(core.OptStr_OutJSON) {
		flushJSON, _ := json.Marshal(result)
		fmt.Println(string(flushJSON))
	} else {
		fmt.Printf("Flushed %d tokens from the blocklist\n", result.Count)
	}
}
