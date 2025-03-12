package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dylantarre/go-lynx/internal/auth"
	"github.com/dylantarre/go-lynx/internal/handlers"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

func main() {
	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Set log level based on environment variable
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logger.Warnf("Invalid log level: %s, defaulting to info", logLevel)
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		logger.Warn("No .env file found, using environment variables")
	}

	// Get configuration from environment variables
	musicDir := os.Getenv("MUSIC_DIR")
	if musicDir == "" {
		musicDir = "/music"
		logger.Warnf("MUSIC_DIR not set, defaulting to %s", musicDir)
	}

	// Make sure the music directory exists
	if _, err := os.Stat(musicDir); os.IsNotExist(err) {
		logger.Warnf("Music directory %s does not exist, creating it", musicDir)
		if err := os.MkdirAll(musicDir, 0755); err != nil {
			logger.Fatalf("Failed to create music directory: %v", err)
		}
	}

	// Get the absolute path to the music directory
	musicDir, err = filepath.Abs(musicDir)
	if err != nil {
		logger.Fatalf("Failed to get absolute path for music directory: %v", err)
	}

	supabaseJWTSecret := os.Getenv("SUPABASE_JWT_SECRET")
	if supabaseJWTSecret == "" {
		logger.Fatal("SUPABASE_JWT_SECRET must be set")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3500"
		logger.Warnf("PORT not set, defaulting to %s", port)
	}

	// Log important configuration
	logger.Infof("Music directory: %s", musicDir)
	logger.Infof("JWT secret length: %d", len(supabaseJWTSecret))
	logger.Infof("Server port: %s", port)

	// Create the app state
	appState := &handlers.AppState{
		MusicDir:          musicDir,
		SupabaseJWTSecret: supabaseJWTSecret,
		Logger:            logger,
	}

	// Create the router
	r := chi.NewRouter()

	// Add middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Add CORS middleware
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "apikey"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Public routes (no authentication required)
	r.Group(func(r chi.Router) {
		r.Get("/health", appState.HealthCheckHandler)
		r.Get("/random", appState.RandomTrackHandler)
		r.Get("/tracks/{id}", appState.StreamTrackHandler)
		r.Post("/prefetch", appState.PrefetchTracksHandler)
	})

	// Protected routes (authentication required)
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(supabaseJWTSecret))
		r.Get("/me", appState.UserInfoHandler)
	})

	// Create the server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: r,
	}

	// Start the server in a goroutine
	go func() {
		logger.Infof("Music streaming server listening on :%s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Create a deadline for server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shut down the server
	logger.Info("Shutting down server...")
	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exiting")
}
