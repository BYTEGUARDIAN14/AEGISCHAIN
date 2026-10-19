package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/byteaegis/aegischain/internal/api"
	"github.com/byteaegis/aegischain/internal/ledger"
	"github.com/byteaegis/aegischain/internal/risk"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	ledgerPath := os.Getenv("LEDGER_PATH")
	if ledgerPath == "" {
		ledgerPath = "bench/results/ledger.jsonl"
	}

	var decLedger *ledger.Ledger
	l, err := ledger.LoadFromFile(ledgerPath)
	if err == nil {
		decLedger = l
		slog.Info("Loaded decision ledger from disk", "path", ledgerPath, "entries", len(l.Entries()))
	} else {
		decLedger = ledger.NewLedger()
		slog.Info("Initialized fresh decision ledger", "path", ledgerPath)
	}

	riskClient := risk.NewClient("http://localhost:8088", 2*time.Second)
	apiServer := api.NewServer(decLedger, riskClient)

	mux := http.NewServeMux()
	apiServer.RegisterRoutes(mux)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	slog.Info("Starting AegisChain Trust Engine REST API", "port", port)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Trust Engine HTTP server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("Shutting down Trust Engine gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Graceful shutdown failed", "error", err)
	}
}
