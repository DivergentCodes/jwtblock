package main

import (
	cmd "divergent.codes/jwt-block/cmd/jwt-block"
	"divergent.codes/jwt-block/internal/core"
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
	cmd.Execute()
}
