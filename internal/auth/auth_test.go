// This file contains tests for the JWT token verification and validation functions used in the application.
// The tests cover various scenarios including valid and invalid JWT tokens, expired tokens, tokens with invalid signatures,
// API key authentication, requests with no authentication, and token validation with different algorithms and secrets.

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// TestVerifyToken_WithValidJWT tests token verification with a valid JWT
func TestVerifyToken_WithValidJWT(t *testing.T) {
	// Create a valid JWT token for testing
	secret := "test_jwt_secret"
	token := createTestJWT(t, secret, time.Hour)
	
	// Create a test request with the token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	
	// Verify the token
	claims, err := VerifyToken(req, secret)
	
	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, "test-user", claims.Sub)
}

// TestVerifyToken_WithExpiredJWT tests token verification with an expired JWT
func TestVerifyToken_WithExpiredJWT(t *testing.T) {
	// Create an expired JWT token for testing
	secret := "test_jwt_secret"
	token := createTestJWT(t, secret, -time.Hour) // Expired 1 hour ago
	
	// Create a test request with the token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	
	// Verify the token
	claims, err := VerifyToken(req, secret)
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "expired")
}

// TestVerifyToken_WithInvalidSignature tests token verification with an invalid signature
func TestVerifyToken_WithInvalidSignature(t *testing.T) {
	// Create a JWT token with one secret
	secret1 := "test_jwt_secret"
	token := createTestJWT(t, secret1, time.Hour)
	
	// Verify with a different secret
	secret2 := "different_secret"
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	
	// Verify the token
	claims, err := VerifyToken(req, secret2)
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "signature")
}

// TestVerifyToken_WithAPIKey tests token verification with an API key
func TestVerifyToken_WithAPIKey(t *testing.T) {
	// Create a test request with an API key
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("apikey", "test-api-key")
	
	// Verify the token
	claims, err := VerifyToken(req, "any_secret")
	
	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, "anon-user", claims.Sub)
	assert.NotNil(t, claims.Role)
	assert.Equal(t, "anon", *claims.Role)
}

// TestVerifyToken_WithNoAuth tests token verification with no authentication
func TestVerifyToken_WithNoAuth(t *testing.T) {
	// Create a test request with no authentication
	req := httptest.NewRequest("GET", "/test", nil)
	
	// Verify the token
	claims, err := VerifyToken(req, "any_secret")
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "no valid authentication")
}

// TestDecodeAndValidateToken_WithValidToken tests token validation with a valid token
func TestDecodeAndValidateToken_WithValidToken(t *testing.T) {
	// Create a valid JWT token for testing
	secret := "test_jwt_secret"
	token := createTestJWT(t, secret, time.Hour)
	
	// Validate the token
	claims, err := decodeAndValidateToken(token, secret)
	
	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, "test-user", claims.Sub)
}

// TestDecodeAndValidateToken_WithTrimmedSecret tests token validation with a secret that has whitespace
func TestDecodeAndValidateToken_WithTrimmedSecret(t *testing.T) {
	// Create a valid JWT token for testing
	secret := "test_jwt_secret"
	token := createTestJWT(t, secret, time.Hour)
	
	// Validate the token with a secret that has whitespace
	secretWithWhitespace := "  " + secret + " \n"
	claims, err := decodeAndValidateToken(token, secretWithWhitespace)
	
	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, "test-user", claims.Sub)
}

// TestDecodeAndValidateToken_WithInvalidAlgorithm tests token validation with an invalid algorithm
func TestDecodeAndValidateToken_WithInvalidAlgorithm(t *testing.T) {
	// Create a test token with a non-HS256 algorithm (this is a mock, not a real token)
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJleHAiOjk5OTk5OTk5OTl9.signature"
	
	// Validate the token
	claims, err := decodeAndValidateToken(tokenString, "any_secret")
	
	// Assert
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "unexpected signing method")
}

// TestTryValidateWithMultipleSecrets tests the multiple secret validation function
func TestTryValidateWithMultipleSecrets(t *testing.T) {
	// Create a valid JWT token for testing
	secret := "test_jwt_secret"
	token := createTestJWT(t, secret, time.Hour)
	
	// Try validating with multiple secrets
	results := TryValidateWithMultipleSecrets(token, secret)
	
	// Assert
	assert.NotNil(t, results)
	assert.Contains(t, results, "algorithm")
	assert.Equal(t, "HS256", results["algorithm"])
	
	// Check original secret attempt
	originalAttempt, ok := results["original"].(map[string]interface{})
	assert.True(t, ok)
	assert.True(t, originalAttempt["success"].(bool))
}

// TestDebugJWTSecret tests the JWT secret debugging function
func TestDebugJWTSecret(t *testing.T) {
	// Test with a normal secret
	secret := "test_jwt_secret123!@#"
	info := DebugJWTSecret(secret)
	
	// Assert
	assert.NotNil(t, info)
	assert.Equal(t, len(secret), info["length"])
	assert.Contains(t, info["character_types"], "alphabetic")
	assert.Contains(t, info["character_types"], "numeric")
	assert.Contains(t, info["character_types"], "special")
	
	// Test with a token-like secret
	tokenSecret := "eyJhbGciOiJIUzI1NiJ9.test"
	tokenInfo := DebugJWTSecret(tokenSecret)
	assert.Contains(t, tokenInfo, "note")
	assert.Contains(t, tokenInfo["note"], "starts with 'ey'")
}

// Helper function to create a test JWT token
func createTestJWT(t *testing.T, secret string, expiration time.Duration) string {
	// Create claims
	claims := &Claims{
		Sub: "test-user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
		},
	}
	
	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	
	// Sign token
	tokenString, err := token.SignedString([]byte(secret))
	assert.NoError(t, err)
	
	return tokenString
} 