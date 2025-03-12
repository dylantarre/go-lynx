package internal

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dylantarre/go-lynx/internal/auth"
	"github.com/dylantarre/go-lynx/internal/handlers"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestServer creates a test server with a temporary music directory
func setupTestServer(t *testing.T) (*httptest.Server, string) {
	// Create a temporary directory for music files
	tempDir, err := ioutil.TempDir("", "music-test")
	require.NoError(t, err)
	
	// Create a test logger
	logger := logrus.New()
	logger.SetOutput(ioutil.Discard) // Silence logs during tests
	
	// Create test JWT secret
	jwtSecret := "test_jwt_secret"
	
	// Create the app state
	appState := &handlers.AppState{
		MusicDir:          tempDir,
		SupabaseJWTSecret: jwtSecret,
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
		r.Get("/debug/public", appState.PublicDebugHandler)
	})
	
	// Protected routes (authentication required)
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(jwtSecret))
		r.Get("/tracks/{id}", appState.StreamTrackHandler)
		r.Post("/prefetch", appState.PrefetchTracksHandler)
		r.Get("/me", appState.UserInfoHandler)
		r.Get("/debug/auth", appState.DebugAuthHandler)
	})
	
	// Create the test server
	server := httptest.NewServer(r)
	
	return server, tempDir
}

// createTestMP3 creates a test MP3 file in the music directory
func createTestMP3(t *testing.T, musicDir, filename string) string {
	// Create a dummy MP3 file
	filePath := filepath.Join(musicDir, filename+".mp3")
	err := ioutil.WriteFile(filePath, []byte("dummy mp3 content"), 0644)
	require.NoError(t, err)
	return filePath
}

// createTestJWT creates a test JWT token
func createTestJWT(t *testing.T, secret string, expiration time.Duration) string {
	// Create claims
	role := "authenticated"
	email := "test@example.com"
	claims := &auth.Claims{
		Sub:   "test-user-id",
		Role:  &role,
		Email: &email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
		},
	}
	
	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	
	// Sign token
	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	
	return tokenString
}

// TestIntegration_HealthCheck tests the health check endpoint
func TestIntegration_HealthCheck(t *testing.T) {
	// Setup
	server, tempDir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)
	
	// Make a request to the health check endpoint
	resp, err := http.Get(server.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestIntegration_RandomTrack tests the random track endpoint
func TestIntegration_RandomTrack(t *testing.T) {
	// Setup
	server, tempDir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)
	
	// Create some test MP3 files
	createTestMP3(t, tempDir, "track1")
	createTestMP3(t, tempDir, "track2")
	
	// Make a request to the random track endpoint
	resp, err := http.Get(server.URL + "/random")
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	
	// Parse the response
	var response map[string]string
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	
	// Check that a track ID was returned
	assert.Contains(t, response, "track_id")
	trackID := response["track_id"]
	assert.Contains(t, []string{"track1", "track2"}, trackID)
}

// TestIntegration_StreamTrack_WithJWT tests the stream track endpoint with JWT authentication
func TestIntegration_StreamTrack_WithJWT(t *testing.T) {
	// Setup
	server, tempDir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)
	
	// Create a test MP3 file
	trackID := "test-track"
	createTestMP3(t, tempDir, trackID)
	
	// Create a JWT token
	token := createTestJWT(t, "test_jwt_secret", time.Hour)
	
	// Create a request with the JWT token
	req, err := http.NewRequest("GET", server.URL+"/tracks/"+trackID, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	
	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "audio/mpeg", resp.Header.Get("Content-Type"))
	
	// Check the response body
	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "dummy mp3 content", string(body))
}

// TestIntegration_StreamTrack_WithAPIKey tests the stream track endpoint with API key authentication
func TestIntegration_StreamTrack_WithAPIKey(t *testing.T) {
	// Setup
	server, tempDir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)
	
	// Create a test MP3 file
	trackID := "test-track"
	createTestMP3(t, tempDir, trackID)
	
	// Create a request with an API key
	req, err := http.NewRequest("GET", server.URL+"/tracks/"+trackID, nil)
	require.NoError(t, err)
	req.Header.Set("apikey", "test-api-key")
	
	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "audio/mpeg", resp.Header.Get("Content-Type"))
	
	// Check the response body
	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "dummy mp3 content", string(body))
}

// TestIntegration_StreamTrack_Unauthorized tests the stream track endpoint without authentication
func TestIntegration_StreamTrack_Unauthorized(t *testing.T) {
	// Setup
	server, tempDir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)
	
	// Create a test MP3 file
	trackID := "test-track"
	createTestMP3(t, tempDir, trackID)
	
	// Make a request without authentication
	resp, err := http.Get(server.URL + "/tracks/" + trackID)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	
	// Parse the response
	var response map[string]string
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	
	// Check the error message
	assert.Contains(t, response, "error")
	assert.Contains(t, response, "detail")
	assert.Equal(t, "No authentication provided", response["error"])
}

// TestIntegration_UserInfo tests the user info endpoint with JWT authentication
func TestIntegration_UserInfo(t *testing.T) {
	// Setup
	server, tempDir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)
	
	// Create a JWT token
	token := createTestJWT(t, "test_jwt_secret", time.Hour)
	
	// Create a request with the JWT token
	req, err := http.NewRequest("GET", server.URL+"/me", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	
	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	
	// Parse the response
	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	
	// Check the user info
	assert.Equal(t, "test-user-id", response["id"])
	assert.Equal(t, "test@example.com", response["email"])
	assert.Equal(t, "authenticated", response["role"])
}

// TestIntegration_PublicDebugEndpoint tests the public debug endpoint
func TestIntegration_PublicDebugEndpoint(t *testing.T) {
	// Setup
	server, tempDir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)
	
	// Make a request to the public debug endpoint
	resp, err := http.Get(server.URL + "/debug/public")
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	
	// Parse the response
	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	
	// Check the debug info
	assert.Contains(t, response, "server_time")
	assert.Contains(t, response, "jwt_secret_info")
	assert.Contains(t, response, "token_info")
	assert.Contains(t, response, "headers")
	assert.Contains(t, response, "server_version")
}

// TestIntegration_ProtectedDebugEndpoint tests the protected debug endpoint
func TestIntegration_ProtectedDebugEndpoint(t *testing.T) {
	// Setup
	server, tempDir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)
	
	// Create a JWT token
	token := createTestJWT(t, "test_jwt_secret", time.Hour)
	
	// Create a request with the JWT token
	req, err := http.NewRequest("GET", server.URL+"/debug/auth", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	
	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	
	// Parse the response
	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
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

// TestIntegration_ExpiredJWT tests authentication with an expired JWT token
func TestIntegration_ExpiredJWT(t *testing.T) {
	// Setup
	server, tempDir := setupTestServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)
	
	// Create an expired JWT token
	token := createTestJWT(t, "test_jwt_secret", -time.Hour) // Expired 1 hour ago
	
	// Create a request with the expired JWT token
	req, err := http.NewRequest("GET", server.URL+"/me", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	
	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	
	// Assert
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	
	// Parse the response
	var response map[string]string
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	
	// Check the error message
	assert.Contains(t, response, "error")
	assert.Contains(t, response, "detail")
	assert.Equal(t, "Token has expired", response["error"])
} 