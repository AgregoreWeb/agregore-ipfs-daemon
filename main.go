package main

import (
	"os"

	"github.com/AgregoreWeb/agregore-ipfs-daemon/gateway"
)

// This file is only used when building a binary for debugging on a desktop machine.

func main() {
	port := "8080"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	exitCode := gateway.RunSynchronous("agregore-ipfs-repo", port, "")
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
