package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/dylantarre/go-lynx/internal/auth"
	"github.com/dylantarre/go-lynx/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// AppState holds the application state
type AppState struct {
	Storage           storage.Storage
	SupabaseJWTSecret string
	Logger            *logrus.Logger
}

// PrefetchRequest represents a request to prefetch tracks
type PrefetchRequest struct {
	TrackIDs []string `json:"track_ids"`
}

// HealthCheckHandler returns a 200 OK response
func (a *AppState) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// RandomTrackHandler returns a random track from the music directory
func (a *AppState) RandomTrackHandler(w http.ResponseWriter, r *http.Request) {
	tracks, err := a.Storage.ListTracks(r.Context())
	if err != nil {
		a.Logger.Errorf("Failed to list tracks: %v", err)
		http.Error(w, "Failed to list tracks", http.StatusInternalServerError)
		return
	}

	if len(tracks) == 0 {
		http.Error(w, "No tracks found", http.StatusNotFound)
		return
	}

	// Get a random track
	rand.Seed(time.Now().UnixNano())
	randomTrack := tracks[rand.Intn(len(tracks))]

	// Return the track ID
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id": randomTrack,
	})
}

// StreamTrackHandler streams a track to the client
func (a *AppState) StreamTrackHandler(w http.ResponseWriter, r *http.Request) {
	trackID := chi.URLParam(r, "id")
	if trackID == "" {
		http.Error(w, "Track ID is required", http.StatusBadRequest)
		return
	}

	// Check if track exists
	exists, err := a.Storage.TrackExists(r.Context(), trackID)
	if err != nil {
		a.Logger.Errorf("Failed to check if track exists: %v", err)
		http.Error(w, "Failed to check if track exists", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "Track not found", http.StatusNotFound)
		return
	}

	// Get content type based on file extension
	contentType := getContentType(trackID)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Accept-Ranges", "bytes")

	// Handle range requests
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		start, end, err := parseRange(rangeHeader)
		if err != nil {
			http.Error(w, "Invalid range header", http.StatusBadRequest)
			return
		}

		reader, err := a.Storage.GetTrackRange(r.Context(), trackID, start, end)
		if err != nil {
			a.Logger.Errorf("Failed to get track range: %v", err)
			http.Error(w, "Failed to get track range", http.StatusInternalServerError)
			return
		}
		defer reader.Close()

		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/*", start, end))
		w.WriteHeader(http.StatusPartialContent)
		io.Copy(w, reader)
		return
	}

	// Stream the entire track
	reader, err := a.Storage.GetTrack(r.Context(), trackID)
	if err != nil {
		a.Logger.Errorf("Failed to get track: %v", err)
		http.Error(w, "Failed to get track", http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	io.Copy(w, reader)
}

// PrefetchTracksHandler checks if tracks exist in the music directory
func (a *AppState) PrefetchTracksHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TrackIDs []string `json:"trackIds"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	results := make(map[string]bool)
	for _, id := range request.TrackIDs {
		exists, err := a.Storage.TrackExists(r.Context(), id)
		if err != nil {
			a.Logger.Errorf("Failed to check if track exists: %v", err)
			results[id] = false
			continue
		}
		results[id] = exists
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// UserInfoHandler returns information about the authenticated user
func (a *AppState) UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// DebugAuthHandler returns debug information for authenticated routes
func (a *AppState) DebugAuthHandler(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "User not found in context", http.StatusUnauthorized)
		return
	}

	debug := map[string]interface{}{
		"headers":      r.Header,
		"method":      r.Method,
		"path":        r.URL.Path,
		"query":       r.URL.Query(),
		"remote_addr": r.RemoteAddr,
		"host":        r.Host,
		"user":        user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(debug)
}

// PublicDebugHandler returns debug information for public routes
func (a *AppState) PublicDebugHandler(w http.ResponseWriter, r *http.Request) {
	debug := map[string]interface{}{
		"headers":      r.Header,
		"method":      r.Method,
		"path":        r.URL.Path,
		"query":       r.URL.Query(),
		"remote_addr": r.RemoteAddr,
		"host":        r.Host,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(debug)
}

// TokenDebugHandler returns debug information about the JWT token
func (a *AppState) TokenDebugHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Initialize debug info with default values
	debugInfo := map[string]interface{}{
		"secret_length": len(a.SupabaseJWTSecret),
		"secret_info": auth.DebugJWTSecret(a.SupabaseJWTSecret),
		"validation_attempts": map[string]interface{}{
			"original": map[string]interface{}{"success": false, "error": "Invalid token format"},
			"trimmed": map[string]interface{}{"success": false, "error": "Invalid token format"},
		},
		// Add default values for backward compatibility with tests
		"algorithm": "unknown",
		"original": map[string]interface{}{"success": false, "error": "Invalid token format"},
		"trimmed": map[string]interface{}{"success": false, "error": "Invalid token format"},
	}
	
	// Extract token from header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		debugInfo["error"] = "No Bearer token provided"
		json.NewEncoder(w).Encode(debugInfo)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	debugInfo["token_length"] = len(tokenString)
	
	// Parse token without validation to extract header and claims
	parser := &jwt.Parser{}
	token, _, err := parser.ParseUnverified(tokenString, &auth.Claims{})
	
	if err != nil {
		debugInfo["parse_error"] = err.Error()
	} else {
		// Add token header info
		debugInfo["token_header"] = token.Header
		
		// Try to extract claims
		if claims, ok := token.Claims.(*auth.Claims); ok {
			debugInfo["token_claims"] = map[string]interface{}{
				"sub": claims.Sub,
				"email": claims.Email,
				"role": claims.Role,
				"aud": claims.Aud,
				"iss": claims.Iss,
			}
			
			if claims.ExpiresAt != nil {
				debugInfo["token_expires_at"] = claims.ExpiresAt.Time
				debugInfo["token_expired"] = time.Now().After(claims.ExpiresAt.Time)
			}
		}
		
		// Try multiple validation attempts
		validationResults := auth.TryValidateWithMultipleSecrets(tokenString, a.SupabaseJWTSecret)
		
		// Copy validation results to debug info
		for k, v := range validationResults {
			debugInfo[k] = v
		}
		
		// Ensure validation_attempts is set
		if validationAttempts, ok := validationResults["validation_attempts"]; ok {
			debugInfo["validation_attempts"] = validationAttempts
		}
	}
	
	// Return debug info
	json.NewEncoder(w).Encode(debugInfo)
}

// Helper functions

func getContentType(filename string) string {
	ext := strings.ToLower(path.Ext(filename))
	switch ext {
	case ".mp3":
		return "audio/mpeg"
	case ".m4a":
		return "audio/mp4"
	case ".flac":
		return "audio/flac"
	case ".wav":
		return "audio/wav"
	case ".ogg":
		return "audio/ogg"
	case ".aac":
		return "audio/aac"
	default:
		return "application/octet-stream"
	}
}

func parseRange(rangeHeader string) (start int64, end int64, err error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, fmt.Errorf("invalid range header format")
	}

	parts := strings.Split(strings.TrimPrefix(rangeHeader, "bytes="), "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range header format")
	}

	start, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start range")
	}

	if parts[1] == "" {
		end = -1 // No end specified
	} else {
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid end range")
		}
	}

	if start < 0 || (end != -1 && end < start) {
		return 0, 0, fmt.Errorf("invalid range values")
	}

	return start, end, nil
}
