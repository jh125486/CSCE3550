package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jh125486/CSCE3550/pkg/cli"
	basecli "github.com/jh125486/gradebot/pkg/cli"
)

var (
	version = ""
	buildID = ""
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var grammar cli.CLI
	if err := basecli.NewKongContext(ctx, "gradebot", buildID, version, &grammar, os.Args[1:]).
		Run(ctx); err != nil {
		log.Fatalf("Failed to execute command: %v", err)
	}
}
