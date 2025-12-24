package handlers

import (
	"database/sql"
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
	"github.com/dylantarre/go-lynx/internal/database"
	"github.com/dylantarre/go-lynx/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
)

// AppState holds the application state
type AppState struct {
	Storage   storage.Storage
	DB        *database.DB
	JWTSecret string
	Logger    *logrus.Logger
}

// AuthRequest represents signup/login request body
type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse represents signup/login response
type AuthResponse struct {
	Token string `json:"token"`
	User  struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

// SignupHandler handles user registration
func (a *AppState) SignupHandler(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		http.Error(w, "Password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	user, err := a.DB.CreateUser(req.Email, req.Password)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "Email already exists", http.StatusConflict)
			return
		}
		a.Logger.Errorf("Failed to create user: %v", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	token, err := auth.GenerateToken(user.ID, user.Email, a.JWTSecret)
	if err != nil {
		a.Logger.Errorf("Failed to generate token: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	resp := AuthResponse{Token: token}
	resp.User.ID = user.ID
	resp.User.Email = user.Email

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// LoginHandler handles user login
func (a *AppState) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	user, err := a.DB.GetUserByEmail(req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
			return
		}
		a.Logger.Errorf("Failed to get user: %v", err)
		http.Error(w, "Failed to authenticate", http.StatusInternalServerError)
		return
	}

	if !a.DB.ValidatePassword(user, req.Password) {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	token, err := auth.GenerateToken(user.ID, user.Email, a.JWTSecret)
	if err != nil {
		a.Logger.Errorf("Failed to generate token: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	resp := AuthResponse{Token: token}
	resp.User.ID = user.ID
	resp.User.Email = user.Email

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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

	rand.Seed(time.Now().UnixNano())
	randomTrack := tracks[rand.Intn(len(tracks))]

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

	contentType := getContentType(trackID)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Accept-Ranges", "bytes")

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
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
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
		end = -1
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
