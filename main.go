package main

import (
	cmd "github.com/divergentcodes/jwtblock/cmd/jwtblock"
	"github.com/divergentcodes/jwtblock/internal/core"
	awslambda "github.com/divergentcodes/jwtblock/serverless/awslambda"
	"github.com/spf13/viper"
)

func init() {
	logger := core.GetLogger()

	// Always start with configured defaults.
	core.InitConfigDefaults()

	logger.Debug("Initialized default configuration")

	logger.Debug(viper.AllSettings())
}

func runCli() {
	err := cmd.Execute()
	if err != nil {
		panic(err)
	}
}

func main() {
	if awslambda.IsAwsLambdaEnv() {
		awslambda.Start()
	} else {
		runCli()
	}
}
