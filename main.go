package main

import (
	"context"
	"os/signal"
	"syscall"

	_ "go.uber.org/automaxprocs"

	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/logger"
	"github.com/pkimetal/pkimetal/server"

	// Register all of the enabled linter backends.
	// External:
	_ "github.com/pkimetal/pkimetal/linter/badkeys"
	_ "github.com/pkimetal/pkimetal/linter/certlint"
	_ "github.com/pkimetal/pkimetal/linter/ftfy"
	_ "github.com/pkimetal/pkimetal/linter/pkilint"

	// Internal:
	_ "github.com/pkimetal/pkimetal/linter/dwklint"
	_ "github.com/pkimetal/pkimetal/linter/rocacheck"
	_ "github.com/pkimetal/pkimetal/linter/x509lint"
	_ "github.com/pkimetal/pkimetal/linter/zlint"
)

func main() {
	// Configure graceful shutdown capabilities.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer logger.Logger.Info("Shutting down")
	defer linter.ShutdownWG.Wait()

	// Start the linters.
	linter.StartLinters(ctx)
	defer linter.StopLinters(ctx)

	// Start the HTTP servers (Web and Monitoring).
	server.Run()
	defer server.Shutdown()

	// Wait to be interrupted.
	<-ctx.Done()

	// Ensure all log messages are flushed before we exit.
	logger.Logger.Sync()
}
