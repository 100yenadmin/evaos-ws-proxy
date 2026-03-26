package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/100yenadmin/evaos-ws-proxy/internal/auth"
	"github.com/100yenadmin/evaos-ws-proxy/internal/health"
	"github.com/100yenadmin/evaos-ws-proxy/internal/proxy"
	"github.com/100yenadmin/evaos-ws-proxy/internal/registry"
)

// Config holds all application configuration parsed from environment variables.
type Config struct {
	ListenAddr               string
	SupabaseURL              string
	SupabaseServiceKey       string
	SupabaseJWTSecret        string
	AdminEmails              []string
	VMCacheTTL               time.Duration
	LogLevel                 slog.Level
	BackendConnectTimeout    time.Duration
	BackendReconnectAttempts int
	MaxConnections           int
	MaxConnectionsPerUser    int
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		ListenAddr:               envOrDefault("LISTEN_ADDR", ":8080"),
		SupabaseURL:              os.Getenv("SUPABASE_URL"),
		SupabaseServiceKey:       os.Getenv("SUPABASE_SERVICE_KEY"),
		SupabaseJWTSecret:        os.Getenv("SUPABASE_JWT_SECRET"),
		VMCacheTTL:               parseDuration("VM_CACHE_TTL", 60*time.Second),
		LogLevel:                 parseLogLevel(os.Getenv("LOG_LEVEL")),
		BackendConnectTimeout:    parseDuration("BACKEND_CONNECT_TIMEOUT", 10*time.Second),
		BackendReconnectAttempts: parseInt("BACKEND_RECONNECT_ATTEMPTS", 3),
		MaxConnections:           parseInt("MAX_CONNECTIONS", 5000),
		MaxConnectionsPerUser:    parseInt("MAX_CONNECTIONS_PER_USER", 10),
	}

	if emails := os.Getenv("ADMIN_EMAILS"); emails != "" {
		for _, e := range strings.Split(emails, ",") {
			if trimmed := strings.TrimSpace(e); trimmed != "" {
				cfg.AdminEmails = append(cfg.AdminEmails, trimmed)
			}
		}
	}

	// Validate required fields
	if cfg.SupabaseURL == "" {
		return nil, fmt.Errorf("SUPABASE_URL is required")
	}
	if cfg.SupabaseServiceKey == "" {
		return nil, fmt.Errorf("SUPABASE_SERVICE_KEY is required")
	}
	// SUPABASE_JWT_SECRET is optional — JWKS (ES256) is the primary auth path.
	// The secret is only needed for legacy HS256 tokens.

	return cfg, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Set up structured JSON logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))
	slog.SetDefault(logger)

	// Build dependencies
	// Build JWKS URL from Supabase project URL
	jwksURL := cfg.SupabaseURL + "/auth/v1/.well-known/jwks.json"
	jwtValidator := auth.NewJWTValidator(cfg.SupabaseJWTSecret, jwksURL)

	// Create a cancellable context for background goroutines (e.g., cache sweep)
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	vmRegistry := registry.NewSupabaseRegistry(appCtx, cfg.SupabaseURL, cfg.SupabaseServiceKey, cfg.VMCacheTTL)
	healthHandler := health.NewHandler()

	// Session manager for cookie-based auth
	// H-2 fix: derive a separate key for session signing instead of reusing Supabase JWT secret directly
	var sessionMgr *proxy.SessionManager
	if cfg.SupabaseJWTSecret != "" {
		sessionKey := proxy.DeriveKey(cfg.SupabaseJWTSecret, "evaos-proxy-session-v1")
		sessionMgr = proxy.NewSessionManager(sessionKey)
		slog.Info("session auth enabled (derived key)")
	} else {
		slog.Warn("session auth disabled — SUPABASE_JWT_SECRET not set")
	}

	proxyHandler := proxy.NewHandler(proxy.HandlerConfig{
		JWTValidator:      jwtValidator,
		VMRegistry:        vmRegistry,
		Health:            healthHandler,
		SessionManager:    sessionMgr,
		AdminEmails:       cfg.AdminEmails,
		ConnectTimeout:    cfg.BackendConnectTimeout,
		ReconnectAttempts: cfg.BackendReconnectAttempts,
		MaxConnections:    cfg.MaxConnections,
		MaxPerUser:        cfg.MaxConnectionsPerUser,
	})

	// Routes
	mux := http.NewServeMux()
	// Health check (registered first — more specific)
	mux.HandleFunc("/health", healthHandler.HandleHealth)
	// Combined WebSocket + HTTP proxy — dispatches based on Upgrade header.
	// Handles both:
	//   /vm/{customer_id}/  (direct access)
	//   /{customer_id}/     (after Traefik strips /vm prefix)
	// WebSocket upgrade requests → HandleWebSocket (existing)
	// Regular HTTP requests → HandleHTTPProxy (static asset proxying)
	mux.Handle("/vm/", proxyHandler)
	mux.Handle("/", proxyHandler)

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		slog.Info("starting ws-proxy",
			"addr", cfg.ListenAddr,
			"max_connections", cfg.MaxConnections,
			"route", "/vm/{customer_id}/",
		)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down, draining connections...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	slog.Info("server stopped")
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseDuration(envKey string, def time.Duration) time.Duration {
	v := os.Getenv(envKey)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		slog.Warn("invalid duration, using default", "key", envKey, "value", v, "default", def)
		return def
	}
	return d
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func parseInt(envKey string, def int) int {
	v := os.Getenv(envKey)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		slog.Warn("invalid int, using default", "key", envKey, "value", v, "default", def)
		return def
	}
	return n
}
