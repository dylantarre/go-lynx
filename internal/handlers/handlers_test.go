package handlers

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dylantarre/go-lynx/internal/auth"
	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestAppState creates a test AppState with a temporary music directory
func setupTestAppState(t *testing.T) (*AppState, string) {
	// Create a temporary directory for music files
	tempDir, err := ioutil.TempDir("", "music-test")
	require.NoError(t, err)
	
	// Create a test logger
	logger := logrus.New()
	logger.SetOutput(ioutil.Discard) // Silence logs during tests
	
	// Create the app state
	appState := &AppState{
		MusicDir:          tempDir,
		SupabaseJWTSecret: "test_jwt_secret",
		Logger:            logger,
	}
	
	return appState, tempDir
}

// createTestMP3 creates a test MP3 file in the music directory
func createTestMP3(t *testing.T, musicDir, filename string) string {
	// Create a dummy MP3 file
	filePath := filepath.Join(musicDir, filename+".mp3")
	err := ioutil.WriteFile(filePath, []byte("dummy mp3 content"), 0644)
	require.NoError(t, err)
	return filePath
}

// createTestContext creates a context with test claims
func createTestContext() context.Context {
	// Create a context with the claims
	return context.WithValue(context.Background(), auth.ContextKey, createTestClaims())
}

// createTestClaims creates test claims for authentication
func createTestClaims() *auth.Claims {
	// Create test claims
	role := "authenticated"
	email := "test@example.com"
	return &auth.Claims{
		Sub:   "test-user-id",
		Role:  &role,
		Email: &email,
	}
}

// TestHealthCheckHandler tests the health check endpoint
func TestHealthCheckHandler(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)
	
	// Create a test request
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	
	// Call the handler
	appState.HealthCheckHandler(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestRandomTrackHandler tests the random track endpoint
func TestRandomTrackHandler(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)
	
	// Create some test MP3 files
	createTestMP3(t, tempDir, "track1")
	createTestMP3(t, tempDir, "track2")
	createTestMP3(t, tempDir, "track3")
	
	// Create a test request
	req := httptest.NewRequest("GET", "/random", nil)
	rr := httptest.NewRecorder()
	
	// Call the handler
	appState.RandomTrackHandler(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	
	// Parse the response
	var response map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	// Check that a track ID was returned
	assert.Contains(t, response, "track_id")
	trackID := response["track_id"]
	assert.Contains(t, []string{"track1", "track2", "track3"}, trackID)
}

// TestRandomTrackHandler_NoTracks tests the random track endpoint when no tracks are available
func TestRandomTrackHandler_NoTracks(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)
	
	// Create a test request
	req := httptest.NewRequest("GET", "/random", nil)
	rr := httptest.NewRecorder()
	
	// Call the handler
	appState.RandomTrackHandler(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	
	// Parse the response
	var response map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	// Check the error message
	assert.Contains(t, response, "error")
	assert.Equal(t, "No tracks found", response["error"])
}

// TestStreamTrackHandler tests the stream track endpoint
func TestStreamTrackHandler(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)
	
	// Create a test MP3 file
	trackID := "test-track"
	createTestMP3(t, tempDir, trackID)
	
	// Create a test request with the track ID in the URL
	req := httptest.NewRequest("GET", "/tracks/"+trackID, nil)
	rr := httptest.NewRecorder()
	
	// Setup the chi router context with URL parameters
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("id", trackID)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx)
	
	// Add authentication context to the same context
	ctx = context.WithValue(ctx, auth.ContextKey, createTestClaims())
	req = req.WithContext(ctx)
	
	// Call the handler
	appState.StreamTrackHandler(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "audio/mpeg", rr.Header().Get("Content-Type"))
	assert.Equal(t, "17", rr.Header().Get("Content-Length")) // Length of "dummy mp3 content"
	assert.Equal(t, "dummy mp3 content", rr.Body.String())
}

// TestStreamTrackHandler_NotFound tests the stream track endpoint with a non-existent track
func TestStreamTrackHandler_NotFound(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)
	
	// Create a test request with a non-existent track ID
	req := httptest.NewRequest("GET", "/tracks/non-existent", nil)
	rr := httptest.NewRecorder()
	
	// Setup the chi router context with URL parameters
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("id", "non-existent")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, chiCtx)
	
	// Add authentication context to the same context
	ctx = context.WithValue(ctx, auth.ContextKey, createTestClaims())
	req = req.WithContext(ctx)
	
	// Call the handler
	appState.StreamTrackHandler(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	
	// Parse the response
	var response map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	// Check the error message
	assert.Contains(t, response, "error")
	assert.Equal(t, "Track not found", response["error"])
}

// TestPrefetchTracksHandler tests the prefetch tracks endpoint
func TestPrefetchTracksHandler(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)
	
	// Create some test MP3 files
	createTestMP3(t, tempDir, "track1")
	createTestMP3(t, tempDir, "track2")
	
	// Create a test request with a JSON body
	reqBody := `{"track_ids": ["track1", "track2", "non-existent"]}`
	req := httptest.NewRequest("POST", "/prefetch", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	
	// Add authentication context
	req = req.WithContext(createTestContext())
	
	// Call the handler
	appState.PrefetchTracksHandler(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	
	// Parse the response
	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	// Check the valid and invalid track IDs
	assert.Contains(t, response, "valid_track_ids")
	assert.Contains(t, response, "invalid_track_ids")
	
	validTracks, ok := response["valid_track_ids"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, validTracks, 2)
	assert.Contains(t, []string{validTracks[0].(string), validTracks[1].(string)}, "track1")
	assert.Contains(t, []string{validTracks[0].(string), validTracks[1].(string)}, "track2")
	
	invalidTracks, ok := response["invalid_track_ids"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, invalidTracks, 1)
	assert.Equal(t, "non-existent", invalidTracks[0].(string))
}

// TestUserInfoHandler tests the user info endpoint
func TestUserInfoHandler(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)
	
	// Create a test request
	req := httptest.NewRequest("GET", "/me", nil)
	rr := httptest.NewRecorder()
	
	// Add authentication context
	req = req.WithContext(createTestContext())
	
	// Call the handler
	appState.UserInfoHandler(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	
	// Parse the response
	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	// Check the user info
	assert.Equal(t, "test-user-id", response["id"])
	assert.Equal(t, "test@example.com", response["email"])
	assert.Equal(t, "authenticated", response["role"])
}

// TestUserInfoHandler_Unauthorized tests the user info endpoint without authentication
func TestUserInfoHandler_Unauthorized(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)
	
	// Create a test request without authentication context
	req := httptest.NewRequest("GET", "/me", nil)
	rr := httptest.NewRecorder()
	
	// Call the handler
	appState.UserInfoHandler(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	
	// Parse the response
	var response map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	// Check the error message
	assert.Contains(t, response, "error")
	assert.Equal(t, "Unauthorized", response["error"])
}

// TestDebugAuthHandler tests the debug auth endpoint
func TestDebugAuthHandler(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)
	
	// Create a test request
	req := httptest.NewRequest("GET", "/debug/auth", nil)
	rr := httptest.NewRecorder()
	
	// Add authentication context
	req = req.WithContext(createTestContext())
	
	// Call the handler
	appState.DebugAuthHandler(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	
	// Parse the response
	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	// Check the debug info
	assert.Equal(t, "authenticated", response["auth_status"])
	assert.Equal(t, "test-user-id", response["user_id"])
	assert.Equal(t, "test@example.com", response["user_email"])
	assert.Equal(t, "authenticated", response["user_role"])
	assert.Contains(t, response, "jwt_secret_info")
	assert.Contains(t, response, "token_info")
	assert.Contains(t, response, "server_time")
}

// TestPublicDebugHandler tests the public debug endpoint
func TestPublicDebugHandler(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)
	
	// Create a test request
	req := httptest.NewRequest("GET", "/debug/public", nil)
	rr := httptest.NewRecorder()
	
	// Call the handler
	appState.PublicDebugHandler(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	
	// Parse the response
	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	// Check the debug info
	assert.Contains(t, response, "server_time")
	assert.Contains(t, response, "jwt_secret_info")
	assert.Contains(t, response, "token_info")
	assert.Contains(t, response, "headers")
	assert.Contains(t, response, "server_version")
}

// TestPublicDebugHandler_WithToken tests the public debug endpoint with a token
func TestPublicDebugHandler_WithToken(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)
	
	// Create a test request with a token
	req := httptest.NewRequest("GET", "/debug/public", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rr := httptest.NewRecorder()
	
	// Call the handler
	appState.PublicDebugHandler(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
	
	// Parse the response
	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	// Check the token info
	tokenInfo, ok := response["token_info"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, true, tokenInfo["present"])
	assert.Contains(t, tokenInfo, "validation_attempts")
}

// TestDebugTokenHandler_NoToken tests the debug token endpoint without a token
func TestDebugTokenHandler_NoToken(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)

	// Create a test request
	req := httptest.NewRequest("GET", "/debug/token", nil)
	rr := httptest.NewRecorder()

	// Call the handler
	appState.TokenDebugHandler(rr, req)

	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	// Parse the response
	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Check that it reports no token
	assert.Contains(t, response, "error")
	assert.Equal(t, "No Bearer token provided", response["error"])
}

// TestDebugTokenHandler_WithInvalidToken tests the debug token endpoint with an invalid token
func TestDebugTokenHandler_WithInvalidToken(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)

	// Create a test request with an invalid token
	req := httptest.NewRequest("GET", "/debug/token", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rr := httptest.NewRecorder()

	// Call the handler
	appState.TokenDebugHandler(rr, req)

	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	// Parse the response
	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Check validation info
	assert.Contains(t, response, "validation_attempts")
	validationAttempts := response["validation_attempts"].(map[string]interface{})
	
	// Check that the validation_attempts map contains the expected keys
	// The algorithm should be in the validation_attempts map from TryValidateWithMultipleSecrets
	assert.Contains(t, response, "algorithm")
	
	// Check that original and trimmed attempts are present
	assert.Contains(t, validationAttempts, "original")
	assert.Contains(t, validationAttempts, "trimmed")
}

// TestDebugTokenHandler_WithValidToken tests the debug token endpoint with a valid token
func TestDebugTokenHandler_WithValidToken(t *testing.T) {
	// Setup
	appState, tempDir := setupTestAppState(t)
	defer os.RemoveAll(tempDir)

	// Create a valid token using the test JWT secret
	claims := createTestClaims()
	token, err := auth.CreateToken(claims, appState.SupabaseJWTSecret)
	require.NoError(t, err)

	// Create a test request with the valid token
	req := httptest.NewRequest("GET", "/debug/token", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	// Call the handler
	appState.TokenDebugHandler(rr, req)

	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	// Parse the response
	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Check validation info
	assert.Contains(t, response, "validation_attempts")
	validationAttempts := response["validation_attempts"].(map[string]interface{})
	
	// Check that original attempt is present and successful
	assert.Contains(t, validationAttempts, "original")
	original := validationAttempts["original"].(map[string]interface{})
	assert.Equal(t, true, original["success"])
	
	// Check that the original attempt is also at the top level
	assert.Contains(t, response, "original")
	topLevelOriginal := response["original"].(map[string]interface{})
	assert.Equal(t, true, topLevelOriginal["success"])

	// Check token info
	assert.Contains(t, response, "token_claims")
	tokenClaims := response["token_claims"].(map[string]interface{})
	assert.Equal(t, claims.Sub, tokenClaims["sub"])
	assert.Equal(t, *claims.Role, tokenClaims["role"])
	assert.Equal(t, *claims.Email, tokenClaims["email"])
} 