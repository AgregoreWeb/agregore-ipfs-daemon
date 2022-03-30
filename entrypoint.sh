#!/usr/bin/env bash

# Tips: From 1.16, it is recommended to execute
# go get -d golang.org/x/mobile/cmd/gomobile
# before each execution of
# gomobile bind ....
# go get will automatically add indirect references to go.mod. These indirect
# references maybe automatically deleted by ide or go mod tidy, but they are required!
#
# From: https://github.com/golang/go/wiki/Mobile#building-and-deploying-to-android-1

go get -d "golang.org/x/mobile/cmd/gomobile@${GOMOBILE_COMMIT}"

# Use args from command line
gomobile "$@"