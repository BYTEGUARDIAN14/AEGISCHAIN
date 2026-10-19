package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		port              string
		tlsCertFile       string
		tlsKeyFile        string
		policiesDir       string
		dataDir           string
		publicKeyPath     string
		breakGlassKeyPath string
		enforceNamespaces string
		auditNamespaces   string
		defaultMode       string
		timeoutSeconds    int
	)

	flag.StringVar(&port, "port", "8443", "Port to listen on for admission webhooks")
	flag.StringVar(&tlsCertFile, "tls-cert-file", "certs/tls.crt", "Path to TLS certificate file")
	flag.StringVar(&tlsKeyFile, "tls-key-file", "certs/tls.key", "Path to TLS private key file")
	flag.StringVar(&policiesDir, "policies-dir", "policies", "Directory containing OPA Rego policies")
	flag.StringVar(&dataDir, "data-dir", "policies/data", "Directory containing policy data and exemptions")
	flag.StringVar(&publicKeyPath, "public-key", "deploy/keys/cosign.pub", "Path to Cosign public key for verification")
	flag.StringVar(&breakGlassKeyPath, "break-glass-key", "", "Path to public key for verifying emergency break-glass tokens")
	flag.StringVar(&enforceNamespaces, "enforce-namespaces", "prod,default", "Comma-separated namespaces where policy is strictly enforced")
	flag.StringVar(&auditNamespaces, "audit-namespaces", "staging,dev", "Comma-separated namespaces running in audit mode")
	flag.StringVar(&defaultMode, "default-mode", "enforce", "Default evaluation mode (enforce | audit)")
	flag.IntVar(&timeoutSeconds, "timeout", 5, "Maximum duration in seconds per admission evaluation")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("Initializing AegisChain Admission Controller",
		"version", "1.0.0",
		"port", port,
		"default_mode", defaultMode,
	)

	// Ensure TLS certificates exist or generate them
	if _, err := os.Stat(tlsCertFile); os.IsNotExist(err) {
		slog.Info("TLS certificate not found; auto-generating self-signed certificate", "cert", tlsCertFile, "key", tlsKeyFile)
		_, err := GenerateSelfSignedCert(tlsCertFile, tlsKeyFile)
		if err != nil {
			slog.Error("Failed to generate self-signed TLS certificates", "error", err)
			os.Exit(1)
		}
	}

	cfg := Config{
		Port:              port,
		TLSCertFile:       tlsCertFile,
		TLSKeyFile:        tlsKeyFile,
		PoliciesDir:       policiesDir,
		DataDir:           dataDir,
		PublicKeyPath:     publicKeyPath,
		BreakGlassKeyPath: breakGlassKeyPath,
		EnforceNamespaces: splitCommaList(enforceNamespaces),
		AuditNamespaces:   splitCommaList(auditNamespaces),
		DefaultMode:       defaultMode,
		Timeout:           time.Duration(timeoutSeconds) * time.Second,
	}

	ctx := context.Background()
	server, err := NewAdmissionServer(ctx, cfg)
	if err != nil {
		slog.Error("Failed to initialize admission server", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("AegisChain Admission Webhook listening with TLS", "port", port, "cert", tlsCertFile)
		if err := httpServer.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil && err != http.ErrServerClosed {
			slog.Error("Admission Webhook server error", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("Gracefully shutting down AegisChain Admission Webhook...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("Admission server graceful shutdown error", "error", err)
	}
	slog.Info("AegisChain Admission Webhook stopped.")
}

func splitCommaList(s string) []string {
	var list []string
	for _, item := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			list = append(list, trimmed)
		}
	}
	return list
}
