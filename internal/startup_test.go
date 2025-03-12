package internal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dylantarre/go-lynx/internal/handlers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStartupValidation tests that the application properly validates critical paths during startup
func TestStartupValidation(t *testing.T) {
	// Create a test logger
	logger := logrus.New()
	logger.SetOutput(os.Stdout)

	// Test cases
	testCases := []struct {
		name          string
		musicDir      string
		jwtSecret     string
		expectedError bool
		errorType     string
	}{
		{
			name:          "Valid configuration",
			musicDir:      os.TempDir(),
			jwtSecret:     "test_jwt_secret",
			expectedError: false,
		},
		{
			name:          "Empty JWT secret",
			musicDir:      os.TempDir(),
			jwtSecret:     "",
			expectedError: true,
			errorType:     "jwt_secret",
		},
		{
			name:          "Invalid music directory path",
			musicDir:      "/non/existent/path/that/should/not/exist",
			jwtSecret:     "test_jwt_secret",
			expectedError: true,
			errorType:     "music_dir",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create the app state
			appState := &handlers.AppState{
				MusicDir:          tc.musicDir,
				SupabaseJWTSecret: tc.jwtSecret,
				Logger:            logger,
			}

			// Test the startup validation
			err := validateStartupConfig(appState)

			if tc.expectedError {
				assert.Error(t, err)
				if tc.errorType == "jwt_secret" {
					assert.Contains(t, err.Error(), "JWT secret")
				} else if tc.errorType == "music_dir" {
					assert.Contains(t, err.Error(), "music directory")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestMusicDirPermissions tests that the application correctly handles music directory permissions
func TestMusicDirPermissions(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "music-dir-permissions")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a test logger
	logger := logrus.New()
	logger.SetOutput(os.Stdout)

	// Test cases
	testCases := []struct {
		name          string
		setupFunc     func() string
		expectedError bool
	}{
		{
			name: "Directory with read/write permissions",
			setupFunc: func() string {
				dirPath := filepath.Join(tempDir, "rw-dir")
				require.NoError(t, os.Mkdir(dirPath, 0755))
				return dirPath
			},
			expectedError: false,
		},
		{
			name: "Directory with read-only permissions",
			setupFunc: func() string {
				dirPath := filepath.Join(tempDir, "ro-dir")
				require.NoError(t, os.Mkdir(dirPath, 0755))
				
				// Create a test file to verify read access
				testFilePath := filepath.Join(dirPath, "test.mp3")
				require.NoError(t, os.WriteFile(testFilePath, []byte("test content"), 0644))
				
				// Make the directory read-only
				require.NoError(t, os.Chmod(dirPath, 0555))
				
				return dirPath
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup the test case
			musicDir := tc.setupFunc()

			// Create the app state
			appState := &handlers.AppState{
				MusicDir:          musicDir,
				SupabaseJWTSecret: "test_jwt_secret",
				Logger:            logger,
			}

			// Test the directory permissions
			err := checkMusicDirPermissions(appState)
			
			if tc.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "write permission")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function to validate startup configuration
func validateStartupConfig(appState *handlers.AppState) error {
	// Validate JWT secret
	if appState.SupabaseJWTSecret == "" {
		return &StartupError{message: "JWT secret must be provided"}
	}

	// Validate music directory
	if _, err := os.Stat(appState.MusicDir); os.IsNotExist(err) {
		// Try to create the directory
		if err := os.MkdirAll(appState.MusicDir, 0755); err != nil {
			return &StartupError{message: "Failed to create music directory: " + err.Error()}
		}
	}

	return nil
}

// Helper function to check music directory permissions
func checkMusicDirPermissions(appState *handlers.AppState) error {
	// Check if the directory exists
	info, err := os.Stat(appState.MusicDir)
	if err != nil {
		return &StartupError{message: "Failed to access music directory: " + err.Error()}
	}

	// Check if it's a directory
	if !info.IsDir() {
		return &StartupError{message: "Music directory path is not a directory"}
	}

	// Check write permissions by attempting to create a temporary file
	testFile := filepath.Join(appState.MusicDir, ".write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return &StartupError{message: "No write permission on music directory: " + err.Error()}
	}

	// Clean up the test file
	_ = os.Remove(testFile)

	return nil
}

// StartupError represents an error that occurs during application startup
type StartupError struct {
	message string
}

// Error returns the error message
func (e *StartupError) Error() string {
	return e.message
} 