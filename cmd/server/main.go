package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dylantarre/go-lynx/internal/auth"
	"github.com/dylantarre/go-lynx/internal/database"
	"github.com/dylantarre/go-lynx/internal/handlers"
	"github.com/dylantarre/go-lynx/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

const (
	VERSION = "1.2.0" // SQLite auth, removed Supabase
)

func main() {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	logger.Infof("Starting Go-Lynx Music Server v%s", VERSION)

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

	if os.Getenv("DO_APP_PLATFORM") == "" {
		if err := godotenv.Load(); err != nil {
			logger.Warn("No .env file found, using environment variables")
		}
	}

	// Initialize SQLite database
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "lynx.db"
	}
	db, err := database.New(dbPath)
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	logger.Infof("Database initialized: %s", dbPath)

	// JWT secret for token signing
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "change-me-in-production"
		logger.Warn("JWT_SECRET not set, using default (insecure for production)")
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

	port := os.Getenv("PORT")
	if port == "" {
		port = "3500"
		logger.Warnf("PORT not set, defaulting to %s", port)
	}

	forceHTTPS := os.Getenv("FORCE_HTTPS") == "true"
	cloudflareEnabled := os.Getenv("CLOUDFLARE_ENABLED") == "true"

	logger.Infof("R2 endpoint: %s", os.Getenv("R2_ENDPOINT"))
	logger.Infof("R2 bucket: %s", os.Getenv("R2_BUCKET"))
	logger.Infof("Server port: %s", port)
	logger.Infof("Force HTTPS: %v", forceHTTPS)
	logger.Infof("Cloudflare enabled: %v", cloudflareEnabled)

	appState := &handlers.AppState{
		Storage:   r2Storage,
		DB:        db,
		JWTSecret: jwtSecret,
		Logger:    logger,
	}

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Path normalization
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// HTTPS upgrade middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !forceHTTPS {
				next.ServeHTTP(w, r)
				return
			}

			cfVisitor := r.Header.Get("CF-Visitor")
			if cloudflareEnabled && cfVisitor != "" {
				if !strings.Contains(cfVisitor, "https") {
					httpsURL := "https://" + r.Host + r.RequestURI
					http.Redirect(w, r, httpsURL, http.StatusPermanentRedirect)
					return
				}
			} else if r.Header.Get("X-Forwarded-Proto") == "http" {
				httpsURL := "https://" + r.Host + r.RequestURI
				http.Redirect(w, r, httpsURL, http.StatusPermanentRedirect)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// Security headers
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if forceHTTPS {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			}
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			next.ServeHTTP(w, r)
		})
	})

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/health", appState.HealthCheckHandler)
		r.Get("/random", appState.RandomTrackHandler)

		// Auth endpoints
		r.Post("/auth/signup", appState.SignupHandler)
		r.Post("/auth/login", appState.LoginHandler)
	})

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(jwtSecret))
		r.Get("/tracks/{id}", appState.StreamTrackHandler)
		r.Post("/prefetch", appState.PrefetchTracksHandler)
		r.Get("/me", appState.UserInfoHandler)
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: r,
	}

	go func() {
		logger.Infof("Music streaming server listening on :%s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger.Info("Shutting down server...")
	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exiting")
}
