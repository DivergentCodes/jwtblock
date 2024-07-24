package main

import (
	cmd "github.com/divergentcodes/jwtblock/cmd/jwtblock"
	"github.com/divergentcodes/jwtblock/internal/core"
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
