package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/divergentcodes/jwt-block/internal/core"
	"github.com/divergentcodes/jwt-block/web"
)

var openapiCmd = &cobra.Command{
	Use:   "openapi",
	Short: "Generate OpenAPI specs for jwt-block",
	Long:  "Generate OpenAPI specs for jwt-block",
	Run:   openapi,
}

func init() {
	openapiCmd.PersistentFlags().String("format", "yaml", "A string flag with limited values (value1, value2)")
	viper.BindPFlag("format", openapiCmd.PersistentFlags().Lookup("format"))

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
