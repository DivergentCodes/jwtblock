package main

import (
	cmd "github.com/divergentcodes/jwt-block/cmd/jwt-block"
	"github.com/divergentcodes/jwt-block/internal/core"
)

func init() {
	logger := core.GetLogger()

	// Always start with configured defaults.
	core.InitConfigDefaults()

	logger.Debug("Initialized default configuration")
}

func main() {
	runCli()
}

func runCli() {
	err := cmd.Execute()
	if err != nil {
		panic(err)
	}
}
