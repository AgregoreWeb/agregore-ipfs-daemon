package main

import (
	"os"

	"github.com/AgregoreWeb/agregore-ipfs-daemon/gateway"
)

// This file is only used when building a binary for debugging on a desktop machine.

func main() {
	exitCode := gateway.Run("agregore-ipfs-repo")
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
