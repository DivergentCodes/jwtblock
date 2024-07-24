package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/divergentcodes/jwtblock/internal/core"
	"github.com/divergentcodes/jwtblock/web"
)

var openapiCmd = &cobra.Command{
	Use:   "openapi",
	Short: "Generate OpenAPI specs for jwtblock",
	Long:  "Generate OpenAPI specs for jwtblock",
	Run:   openapi,
}

func init() {
	logger := core.GetLogger()

	openapiCmd.PersistentFlags().String("format", "yaml", "format for OpenAPI specs (yaml or json)")
	err := viper.BindPFlag("format", openapiCmd.PersistentFlags().Lookup("format"))
	if err != nil {
		logger.Fatalw(err.Error())
	}

	rootCmd.AddCommand(openapiCmd)
}

func openapi(cmd *cobra.Command, args []string) {
	logger := core.GetLogger()

	format := viper.GetString("format")
	schema, err := web.GenerateOpenAPI(format)
	if err != nil {
		logger.Fatalw(err.Error())
	}

	fmt.Print(schema)
}
