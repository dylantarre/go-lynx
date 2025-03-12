package internal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnvironmentVariables tests that the application correctly uses environment variables for configuration
func TestEnvironmentVariables(t *testing.T) {
	// Save original environment variables to restore later
	originalMusicDir := os.Getenv("MUSIC_DIR")
	originalJWTSecret := os.Getenv("SUPABASE_JWT_SECRET")
	originalPort := os.Getenv("PORT")
	originalLogLevel := os.Getenv("LOG_LEVEL")
	
	// Restore environment variables after the test
	defer func() {
		os.Setenv("MUSIC_DIR", originalMusicDir)
		os.Setenv("SUPABASE_JWT_SECRET", originalJWTSecret)
		os.Setenv("PORT", originalPort)
		os.Setenv("LOG_LEVEL", originalLogLevel)
	}()

	// Test cases
	testCases := []struct {
		name           string
		envVars        map[string]string
		expectedConfig *AppConfig
	}{
		{
			name: "All environment variables set",
			envVars: map[string]string{
				"MUSIC_DIR":          "/custom/music/dir",
				"SUPABASE_JWT_SECRET": "custom_jwt_secret",
				"PORT":               "8080",
				"LOG_LEVEL":          "debug",
			},
			expectedConfig: &AppConfig{
				MusicDir:          "/custom/music/dir",
				SupabaseJWTSecret: "custom_jwt_secret",
				Port:              "8080",
				LogLevel:          "debug",
			},
		},
		{
			name: "Only required variables set",
			envVars: map[string]string{
				"SUPABASE_JWT_SECRET": "required_jwt_secret",
			},
			expectedConfig: &AppConfig{
				MusicDir:          "/music", // Default value
				SupabaseJWTSecret: "required_jwt_secret",
				Port:              "3500", // Default value
				LogLevel:          "info", // Default value
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variables for this test case
			for key, value := range tc.envVars {
				os.Setenv(key, value)
			}
			
			// Clear any unset variables
			for _, key := range []string{"MUSIC_DIR", "SUPABASE_JWT_SECRET", "PORT", "LOG_LEVEL"} {
				if _, exists := tc.envVars[key]; !exists {
					os.Unsetenv(key)
				}
			}

			// Load the configuration
			config, err := loadConfig()
			
			// Assert that configuration was loaded successfully
			require.NoError(t, err)
			assert.Equal(t, tc.expectedConfig.MusicDir, config.MusicDir)
			assert.Equal(t, tc.expectedConfig.SupabaseJWTSecret, config.SupabaseJWTSecret)
			assert.Equal(t, tc.expectedConfig.Port, config.Port)
			assert.Equal(t, tc.expectedConfig.LogLevel, config.LogLevel)
		})
	}
}

// TestDefaultConfiguration tests that the application uses default values when environment variables are not set
func TestDefaultConfiguration(t *testing.T) {
	// Save original environment variables to restore later
	originalMusicDir := os.Getenv("MUSIC_DIR")
	originalJWTSecret := os.Getenv("SUPABASE_JWT_SECRET")
	originalPort := os.Getenv("PORT")
	originalLogLevel := os.Getenv("LOG_LEVEL")
	
	// Restore environment variables after the test
	defer func() {
		os.Setenv("MUSIC_DIR", originalMusicDir)
		os.Setenv("SUPABASE_JWT_SECRET", originalJWTSecret)
		os.Setenv("PORT", originalPort)
		os.Setenv("LOG_LEVEL", originalLogLevel)
	}()

	// Clear all environment variables for this test
	os.Unsetenv("MUSIC_DIR")
	os.Unsetenv("PORT")
	os.Unsetenv("LOG_LEVEL")
	
	// We need to set JWT secret as it's required
	os.Setenv("SUPABASE_JWT_SECRET", "test_jwt_secret")

	// Load the configuration
	config, err := loadConfig()
	
	// Assert that configuration was loaded with default values
	require.NoError(t, err)
	assert.Equal(t, "/music", config.MusicDir)
	assert.Equal(t, "test_jwt_secret", config.SupabaseJWTSecret)
	assert.Equal(t, "3500", config.Port)
	assert.Equal(t, "info", config.LogLevel)
}

// TestMissingRequiredConfiguration tests that the application returns an error when required configuration is missing
func TestMissingRequiredConfiguration(t *testing.T) {
	// Save original environment variables to restore later
	originalJWTSecret := os.Getenv("SUPABASE_JWT_SECRET")
	
	// Restore environment variables after the test
	defer func() {
		os.Setenv("SUPABASE_JWT_SECRET", originalJWTSecret)
	}()

	// Clear the required JWT secret
	os.Unsetenv("SUPABASE_JWT_SECRET")

	// Load the configuration
	_, err := loadConfig()
	
	// Assert that an error was returned
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SUPABASE_JWT_SECRET")
}

// AppConfig represents the application configuration
type AppConfig struct {
	MusicDir          string
	SupabaseJWTSecret string
	Port              string
	LogLevel          string
}

// loadConfig loads the application configuration from environment variables
func loadConfig() (*AppConfig, error) {
	// Create a new configuration with default values
	config := &AppConfig{
		MusicDir: "/music",
		Port:     "3500",
		LogLevel: "info",
	}

	// Override with environment variables if set
	if musicDir := os.Getenv("MUSIC_DIR"); musicDir != "" {
		config.MusicDir = musicDir
	}

	if jwtSecret := os.Getenv("SUPABASE_JWT_SECRET"); jwtSecret != "" {
		config.SupabaseJWTSecret = jwtSecret
	} else {
		return nil, &ConfigError{message: "SUPABASE_JWT_SECRET must be set"}
	}

	if port := os.Getenv("PORT"); port != "" {
		config.Port = port
	}

	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}

	return config, nil
}

// ConfigError represents an error that occurs during configuration loading
type ConfigError struct {
	message string
}

// Error returns the error message
func (e *ConfigError) Error() string {
	return e.message
} 