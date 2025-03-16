package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dylantarre/go-lynx/internal/auth"
	"github.com/dylantarre/go-lynx/internal/handlers"
	"github.com/dylantarre/go-lynx/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

const (
	// Update this version number with each deployment
	VERSION = "1.1.2"  // Updated for HTTPS/Cloudflare support
)

func main() {
	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Print version banner
	logger.Infof("🎵 Starting Go-Lynx Music Server v%s 🎵", VERSION)

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

	// Load environment variables from .env file (only in development)
	if os.Getenv("DO_APP_PLATFORM") == "" {
		if err := godotenv.Load(); err != nil {
			logger.Warn("No .env file found, using environment variables")
		}
	}

	// Get music directory from environment variable or use default
	musicDir := os.Getenv("MUSIC_DIR")
	if musicDir == "" {
		// Get the current working directory
		cwd, err := os.Getwd()
		if err != nil {
			logger.Fatalf("Failed to get current working directory: %v", err)
		}
		musicDir = filepath.Join(cwd, "music")
		logger.Warnf("MUSIC_DIR not set, defaulting to %s", musicDir)
	}

	// Create music directory if it doesn't exist
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

	// Initialize R2 storage
	r2Storage, err := storage.NewR2Storage(
		os.Getenv("R2_ENDPOINT"),
		os.Getenv("R2_ACCESS_KEY_ID"),
		os.Getenv("R2_SECRET_ACCESS_KEY"),
		os.Getenv("R2_BUCKET"),
	)
	if err != nil {
		logger.Fatalf("Failed to initialize R2 storage: %v", err)
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

	// Get SSL configuration
	forceHTTPS := os.Getenv("FORCE_HTTPS") == "true"
	cloudflareEnabled := os.Getenv("CLOUDFLARE_ENABLED") == "true"

	// Log important configuration
	logger.Infof("Music directory: %s", musicDir)
	logger.Infof("R2 endpoint: %s", os.Getenv("R2_ENDPOINT"))
	logger.Infof("R2 bucket: %s", os.Getenv("R2_BUCKET"))
	logger.Infof("JWT secret length: %d", len(supabaseJWTSecret))
	logger.Infof("Server port: %s", port)
	logger.Infof("Force HTTPS: %v", forceHTTPS)
	logger.Infof("Cloudflare enabled: %v", cloudflareEnabled)

	// Create the app state
	appState := &handlers.AppState{
		Storage:           r2Storage,
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
	
	// Add debug logging middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.WithFields(logrus.Fields{
				"path":         r.URL.Path,
				"raw_path":     r.URL.RawPath,
				"request_uri":  r.RequestURI,
				"host":         r.Host,
				"method":       r.Method,
				"remote_addr":  r.RemoteAddr,
				"headers":      r.Header,
			}).Info("Incoming request")
			next.ServeHTTP(w, r)
		})
	})
	
	// Add path normalization middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Clean the path by removing double slashes and trailing slash
			path := r.URL.Path
			for len(path) > 0 && path[0] == '/' {
				path = path[1:]
			}
			if path == "" {
				path = "/"
			} else {
				path = "/" + path
			}
			r.URL.Path = path
			next.ServeHTTP(w, r)
		})
	})

	// Add CORS middleware with specific origin for production
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},  // Allow all origins during development
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "apikey"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Add HTTPS upgrade middleware for Cloudflare
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only enforce HTTPS if configured
			if !forceHTTPS {
				next.ServeHTTP(w, r)
				return
			}

			// Check if we're behind Cloudflare
			cfVisitor := r.Header.Get("CF-Visitor")
			if cloudflareEnabled && cfVisitor != "" {
				// If the request came through Cloudflare but isn't HTTPS, redirect to HTTPS
				if !strings.Contains(cfVisitor, "https") {
					httpsURL := "https://" + r.Host + r.RequestURI
					http.Redirect(w, r, httpsURL, http.StatusPermanentRedirect)
					return
				}
			} else if r.Header.Get("X-Forwarded-Proto") == "http" {
				// Handle non-Cloudflare HTTPS redirect
				httpsURL := "https://" + r.Host + r.RequestURI
				http.Redirect(w, r, httpsURL, http.StatusPermanentRedirect)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// Add secure headers middleware with Cloudflare support
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set HSTS header for HTTPS
			if forceHTTPS {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			}
			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			// Add Cloudflare-specific headers
			if cloudflareEnabled {
				w.Header().Set("Expect-CT", "max-age=86400, enforce")
				if r.Header.Get("CF-Visitor") != "" {
					w.Header().Set("X-Forwarded-Proto", "https")
				}
			}
			next.ServeHTTP(w, r)
		})
	})

	// Public routes (no authentication required)
	r.Group(func(r chi.Router) {
		r.Get("/health", appState.HealthCheckHandler)
		r.Get("/random", appState.RandomTrackHandler)
		r.Get("/debug/public", appState.PublicDebugHandler)
		r.Get("/debug/token", appState.TokenDebugHandler)
	})

	// Protected routes (authentication required)
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(supabaseJWTSecret))
		r.Get("/tracks/{id}", appState.StreamTrackHandler)
		r.Post("/prefetch", appState.PrefetchTracksHandler)
		r.Get("/me", appState.UserInfoHandler)
		r.Get("/debug/auth", appState.DebugAuthHandler)
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
