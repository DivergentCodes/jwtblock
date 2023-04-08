package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/divergentcodes/jwt-block/internal/core"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of jwt-block",
	Long:  `Print the version of jwt-block`,
	Run:   version,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func version(cmd *cobra.Command, args []string) {
	ShowBanner()

	fmt.Println(core.Version)
}
