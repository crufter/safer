package main

import (
	"os"

	safercmd "github.com/crufter/safer/cmd/safer"
)

func main() {
	os.Exit(safercmd.Execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
