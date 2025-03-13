package handlers

import (
	"encoding/json"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dylantarre/go-lynx/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// AppState holds the application state
type AppState struct {
	MusicDir          string
	SupabaseJWTSecret string
	Logger            *logrus.Logger
}

// PrefetchRequest represents a request to prefetch tracks
type PrefetchRequest struct {
	TrackIDs []string `json:"track_ids"`
}

// HealthCheckHandler handles health check requests
func (a *AppState) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// RandomTrackHandler returns a random track ID
func (a *AppState) RandomTrackHandler(w http.ResponseWriter, r *http.Request) {
	a.Logger.Info("Received request to /random endpoint")

	// Try to authenticate but don't require it for this endpoint
	_, _ = auth.VerifyToken(r, a.SupabaseJWTSecret)

	// Get all MP3 files from the music directory
	var trackIDs []string

	a.Logger.Infof("Searching for MP3 files in: %s", a.MusicDir)

	err := filepath.WalkDir(a.MusicDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".mp3") {
			// Remove the .mp3 extension to get the track ID
			trackID := strings.TrimSuffix(d.Name(), ".mp3")
			trackIDs = append(trackIDs, trackID)
			a.Logger.Debugf("Added track ID: %s", trackID)
		}
		return nil
	})

	if err != nil {
		a.Logger.Errorf("Failed to read music directory: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	a.Logger.Infof("Found %d MP3 tracks", len(trackIDs))

	if len(trackIDs) == 0 {
		a.Logger.Error("No tracks found in music directory")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "No tracks found"})
		return
	}

	// Choose a random track
	rand.Seed(time.Now().UnixNano())
	trackID := trackIDs[rand.Intn(len(trackIDs))]
	a.Logger.Infof("Selected random track: %s", trackID)

	// Return a JSON response with the track ID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"track_id": trackID})
}

// StreamTrackHandler streams a track by ID
func (a *AppState) StreamTrackHandler(w http.ResponseWriter, r *http.Request) {
	// Get the track ID from the URL
	trackID := chi.URLParam(r, "id")
	if trackID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Track ID is required"})
		return
	}

	// Construct the file path
	filePath := filepath.Join(a.MusicDir, trackID+".mp3")

	// Check if the file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "Track not found"})
		} else {
			a.Logger.Errorf("Error accessing file: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Internal Server Error"})
		}
		return
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		a.Logger.Errorf("Error opening file: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal Server Error"})
		return
	}
	defer file.Close()

	// Get the file size
	fileSize := fileInfo.Size()

	// Check if the client requested a range
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		// Parse the range header
		parts := strings.Split(strings.TrimPrefix(rangeHeader, "bytes="), "-")
		if len(parts) != 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Range header"})
			return
		}

		// Parse the start and end positions
		start, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Range header"})
			return
		}

		var end int64
		if parts[1] == "" {
			end = fileSize - 1
		} else {
			end, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Range header"})
				return
			}
		}

		// Validate the range
		if start >= fileSize || end >= fileSize || start > end {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Range"})
			return
		}

		// Set the content range header
		w.Header().Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10)+"/"+strconv.FormatInt(fileSize, 10))
		w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.Header().Set("Content-Type", "audio/mpeg")
		w.WriteHeader(http.StatusPartialContent)

		// Seek to the start position
		_, err = file.Seek(start, io.SeekStart)
		if err != nil {
			a.Logger.Errorf("Error seeking file: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Copy the requested range to the response
		_, err = io.CopyN(w, file, end-start+1)
		if err != nil {
			a.Logger.Errorf("Error copying file: %v", err)
			return
		}
	} else {
		// Stream the entire file
		w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
		w.Header().Set("Content-Type", "audio/mpeg")
		w.WriteHeader(http.StatusOK)

		// Copy the file to the response
		_, err = io.Copy(w, file)
		if err != nil {
			a.Logger.Errorf("Error copying file: %v", err)
			return
		}
	}
}

// PrefetchTracksHandler handles prefetch requests
func (a *AppState) PrefetchTracksHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the request body
	var req PrefetchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	// Check if all requested track IDs exist
	var validTrackIDs []string
	var invalidTrackIDs []string

	for _, trackID := range req.TrackIDs {
		filePath := filepath.Join(a.MusicDir, trackID+".mp3")
		if _, err := os.Stat(filePath); err == nil {
			validTrackIDs = append(validTrackIDs, trackID)
		} else {
			invalidTrackIDs = append(invalidTrackIDs, trackID)
		}
	}

	// Return a response with the valid and invalid track IDs
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid_track_ids":   validTrackIDs,
		"invalid_track_ids": invalidTrackIDs,
	})
}

// UserInfoHandler returns information about the authenticated user
func (a *AppState) UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	// Get the claims from the context
	claims, ok := auth.GetClaims(r.Context())
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	// Return the user info
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":    claims.Sub,
		"email": claims.Email,
		"role":  claims.Role,
	})
}

// DebugAuthHandler provides debugging information for authentication
func (a *AppState) DebugAuthHandler(w http.ResponseWriter, r *http.Request) {
	a.Logger.Info("Received request to /debug/auth endpoint")
	
	// Get claims from context (already validated by middleware)
	claims, ok := auth.GetClaims(r.Context())
	if !ok {
		a.Logger.Warn("No claims found in context, this should not happen with auth middleware")
		http.Error(w, "Authentication error", http.StatusInternalServerError)
		return
	}
	
	// Create a safe version of the JWT secret info
	secretInfo := auth.DebugJWTSecret(a.SupabaseJWTSecret)
	
	// Extract token from header for additional debugging
	authHeader := r.Header.Get("Authorization")
	tokenDebugInfo := map[string]interface{}{
		"present": authHeader != "" && strings.HasPrefix(authHeader, "Bearer "),
	}
	
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		
		// Parse without validation to extract header info
		parser := &jwt.Parser{}
		token, _, err := parser.ParseUnverified(tokenString, &jwt.MapClaims{})
		
		if err == nil {
			tokenDebugInfo["header"] = token.Header
			
			// Add expiration info if available
			if claims.ExpiresAt != nil {
				tokenDebugInfo["expires_at"] = claims.ExpiresAt.Time
				tokenDebugInfo["expired"] = time.Now().After(claims.ExpiresAt.Time)
				tokenDebugInfo["time_until_expiry"] = claims.ExpiresAt.Time.Sub(time.Now()).String()
			}
		}
	}
	
	// Prepare response
	response := map[string]interface{}{
		"auth_status": "authenticated",
		"user_id": claims.Sub,
		"user_email": claims.Email,
		"user_role": claims.Role,
		"jwt_secret_info": secretInfo,
		"token_info": tokenDebugInfo,
		"server_time": time.Now(),
	}
	
	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// PublicDebugHandler provides debugging information without requiring authentication
func (a *AppState) PublicDebugHandler(w http.ResponseWriter, r *http.Request) {
	a.Logger.Info("Received request to /debug/public endpoint")
	
	// Create a safe version of the JWT secret info
	secretInfo := auth.DebugJWTSecret(a.SupabaseJWTSecret)
	
	// Extract token from header for debugging
	authHeader := r.Header.Get("Authorization")
	tokenDebugInfo := map[string]interface{}{
		"present": authHeader != "" && strings.HasPrefix(authHeader, "Bearer "),
	}
	
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		
		// Try to validate the token with multiple secret formats
		validationResults := auth.TryValidateWithMultipleSecrets(tokenString, a.SupabaseJWTSecret)
		tokenDebugInfo["validation_attempts"] = validationResults
		
		// Parse without validation to extract header info
		parser := &jwt.Parser{}
		token, _, err := parser.ParseUnverified(tokenString, &jwt.MapClaims{})
		
		if err == nil {
			tokenDebugInfo["header"] = token.Header
			
			// Try to extract claims for debugging
			if claims, ok := token.Claims.(*jwt.MapClaims); ok {
				// Only include non-sensitive claims
				safeClaimsMap := make(map[string]interface{})
				
				// Extract expiration time if available
				if exp, ok := (*claims)["exp"].(float64); ok {
					expTime := time.Unix(int64(exp), 0)
					tokenDebugInfo["expires_at"] = expTime
					tokenDebugInfo["expired"] = time.Now().After(expTime)
					tokenDebugInfo["time_until_expiry"] = expTime.Sub(time.Now()).String()
				}
				
				// Include algorithm and token type
				if alg, ok := token.Header["alg"].(string); ok {
					safeClaimsMap["alg"] = alg
				}
				if typ, ok := token.Header["typ"].(string); ok {
					safeClaimsMap["typ"] = typ
				}
				
				tokenDebugInfo["safe_claims"] = safeClaimsMap
			}
		} else {
			tokenDebugInfo["parse_error"] = err.Error()
		}
	}
	
	// Log all headers for debugging
	headers := make(map[string][]string)
	for name, values := range r.Header {
		if !strings.EqualFold(name, "Authorization") && !strings.EqualFold(name, "apikey") {
			headers[name] = values
		} else {
			headers[name] = []string{"[REDACTED]"}
		}
	}
	
	// Prepare response
	response := map[string]interface{}{
		"server_time": time.Now(),
		"jwt_secret_info": secretInfo,
		"token_info": tokenDebugInfo,
		"headers": headers,
		"server_version": "1.1.0", // Match version with main.go
	}
	
	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
