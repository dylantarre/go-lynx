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

	"github.com/dylantarre/go-cassowary/internal/auth"
	"github.com/go-chi/chi/v5"
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
		http.Error(w, "Track ID is required", http.StatusBadRequest)
		return
	}

	// Construct the file path
	filePath := filepath.Join(a.MusicDir, trackID+".mp3")

	// Check if the file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Track not found", http.StatusNotFound)
		} else {
			a.Logger.Errorf("Error accessing file: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		a.Logger.Errorf("Error opening file: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
			http.Error(w, "Invalid Range header", http.StatusBadRequest)
			return
		}

		// Parse the start and end positions
		start, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			http.Error(w, "Invalid Range header", http.StatusBadRequest)
			return
		}

		var end int64
		if parts[1] == "" {
			end = fileSize - 1
		} else {
			end, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				http.Error(w, "Invalid Range header", http.StatusBadRequest)
				return
			}
		}

		// Validate the range
		if start >= fileSize || end >= fileSize || start > end {
			http.Error(w, "Invalid Range", http.StatusRequestedRangeNotSatisfiable)
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
		http.Error(w, "Invalid request body", http.StatusBadRequest)
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
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
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
