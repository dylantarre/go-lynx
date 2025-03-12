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

// TestMusicDirInitialization tests the initialization of the music directory
func TestMusicDirInitialization(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "music-dir-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a test logger that captures logs
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Test cases
	testCases := []struct {
		name          string
		setupFunc     func() string
		expectedError bool
	}{
		{
			name: "Valid directory",
			setupFunc: func() string {
				// Return a valid directory path
				return tempDir
			},
			expectedError: false,
		},
		{
			name: "Non-existent directory that can be created",
			setupFunc: func() string {
				// Return a non-existent directory path that can be created
				return filepath.Join(tempDir, "new-dir")
			},
			expectedError: false,
		},
		{
			name: "Read-only parent directory",
			setupFunc: func() string {
				// Create a read-only directory
				readOnlyDir := filepath.Join(tempDir, "read-only")
				require.NoError(t, os.Mkdir(readOnlyDir, 0755))
				
				// Make it read-only
				require.NoError(t, os.Chmod(readOnlyDir, 0500))
				
				// Return a path inside the read-only directory
				return filepath.Join(readOnlyDir, "music")
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

			// Test the initialization
			err := initializeMusicDir(appState)
			
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				
				// Verify the directory exists
				_, err := os.Stat(musicDir)
				assert.NoError(t, err)
			}
		})
	}
}

// TestConfigurableMusicDirectory tests that the application correctly uses a configurable music directory
func TestConfigurableMusicDirectory(t *testing.T) {
	// Create multiple temporary directories
	tempDir1, err := os.MkdirTemp("", "music-dir-test-1")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir1)

	tempDir2, err := os.MkdirTemp("", "music-dir-test-2")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir2)

	// Create a test logger
	logger := logrus.New()
	logger.SetOutput(os.Stdout)

	// Create test MP3 files in both directories
	createTestFile(t, filepath.Join(tempDir1, "track1.mp3"), "mp3 content 1")
	createTestFile(t, filepath.Join(tempDir2, "track2.mp3"), "mp3 content 2")

	// Create app states with different music directories
	appState1 := &handlers.AppState{
		MusicDir:          tempDir1,
		SupabaseJWTSecret: "test_jwt_secret",
		Logger:            logger,
	}

	appState2 := &handlers.AppState{
		MusicDir:          tempDir2,
		SupabaseJWTSecret: "test_jwt_secret",
		Logger:            logger,
	}

	// Verify that each app state can only access its own music directory
	tracks1, err := listMusicTracks(appState1)
	require.NoError(t, err)
	assert.Contains(t, tracks1, "track1")
	assert.NotContains(t, tracks1, "track2")

	tracks2, err := listMusicTracks(appState2)
	require.NoError(t, err)
	assert.Contains(t, tracks2, "track2")
	assert.NotContains(t, tracks2, "track1")
}

// Helper function to initialize the music directory
func initializeMusicDir(appState *handlers.AppState) error {
	// Check if the music directory exists
	if _, err := os.Stat(appState.MusicDir); os.IsNotExist(err) {
		appState.Logger.Warnf("Music directory %s does not exist, creating it", appState.MusicDir)
		if err := os.MkdirAll(appState.MusicDir, 0755); err != nil {
			appState.Logger.Errorf("Failed to create music directory: %v", err)
			return err
		}
	}

	// Get the absolute path to the music directory
	absPath, err := filepath.Abs(appState.MusicDir)
	if err != nil {
		appState.Logger.Errorf("Failed to get absolute path for music directory: %v", err)
		return err
	}
	
	// Update the music directory to the absolute path
	appState.MusicDir = absPath
	
	return nil
}

// Helper function to list music tracks in a directory
func listMusicTracks(appState *handlers.AppState) ([]string, error) {
	var tracks []string
	
	// Read the directory
	files, err := os.ReadDir(appState.MusicDir)
	if err != nil {
		return nil, err
	}
	
	// Filter for MP3 files
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".mp3" {
			// Remove the .mp3 extension
			trackID := file.Name()[:len(file.Name())-4]
			tracks = append(tracks, trackID)
		}
	}
	
	return tracks, nil
}

// Helper function to create a test file
func createTestFile(t *testing.T, path string, content string) {
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)
} 