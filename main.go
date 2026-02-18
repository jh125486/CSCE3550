package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jh125486/CSCE3550/pkg/cli"
	basecli "github.com/jh125486/gradebot/pkg/cli"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var grammar cli.CLI
	if err := basecli.NewKongContext(ctx, "gradebot", version, commit, date, &grammar, os.Args[1:]).
		Run(ctx); err != nil {
		log.Fatalf("Failed to execute command: %v", err)
	}

	// tiny grace period for logs to flush
	time.Sleep(10 * time.Millisecond)
}
