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

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get status of the blocklist",
	Long:  `Get status of the blocklist`,
	Run:   status,
}

// A StatusData contains the status of the blocklist.
type StatusData struct {
	Size int64 `json:"size"`
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func status(cmd *cobra.Command, args []string) {
	ShowBanner()
	redisDB := cache.GetRedisClient()

	size, err := blocklist.Size(redisDB)

	if viper.GetBool(core.OptStr_OutJSON) {
		statusData := StatusData{
			Size: size,
		}
		statusJSON, _ := json.Marshal(statusData)

		fmt.Println(string(statusJSON))
	} else {
		if err != nil {
			fmt.Printf("Error getting blocklist size: %s", err.Error())
			return
		}

		fmt.Printf("Blocklist size: %d\n", size)
	}
}
