package auth

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSupabaseJWTAuthentication tests authentication with a Supabase-like JWT token
func TestSupabaseJWTAuthentication(t *testing.T) {
	// Create a Supabase-like JWT token with the specific structure mentioned in the issue
	claims := &Claims{
		Sub:   "98bb060d-ad5b-40fe-a7c8-9c8748f09805",
		Role:  stringPtr("authenticated"),
		Email: stringPtr("dylan@lambgoat.com"),
		Aud:   stringPtr("authenticated"),
		Iss:   stringPtr("https://fpuueievvvxbgbqtkjyd.supabase.co/auth/v1"),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	// Create token with HS256 algorithm and kid header
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "KnzECV5i9h/u4BMW" // Add the Key ID as mentioned in the issue

	// Sign the token with a test secret
	jwtSecret := "your_test_jwt_secret"
	tokenString, err := token.SignedString([]byte(jwtSecret))
	require.NoError(t, err)

	// Create a test request with the token
	req := httptest.NewRequest("GET", "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	// Verify the token
	resultClaims, err := VerifyToken(req, jwtSecret)

	// Assert that verification succeeds
	assert.NoError(t, err, "JWT verification should succeed")
	if err != nil {
		t.Logf("JWT verification error: %v", err)
	}
	
	// Verify the claims
	if assert.NotNil(t, resultClaims, "Claims should not be nil") {
		assert.Equal(t, "98bb060d-ad5b-40fe-a7c8-9c8748f09805", resultClaims.Sub)
		assert.Equal(t, "dylan@lambgoat.com", *resultClaims.Email)
		assert.Equal(t, "authenticated", *resultClaims.Role)
		assert.Equal(t, "authenticated", *resultClaims.Aud)
		assert.Equal(t, "https://fpuueievvvxbgbqtkjyd.supabase.co/auth/v1", *resultClaims.Iss)
	}
}

// TestSupabaseJWTWithKID tests that tokens with a Key ID (kid) in the header are properly validated
func TestSupabaseJWTWithKID(t *testing.T) {
	// Create a simple claims object
	claims := &Claims{
		Sub:   "test-user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	// Create token with HS256 algorithm and kid header
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "test-kid" // Add a Key ID

	// Sign the token
	jwtSecret := "test_jwt_secret"
	tokenString, err := token.SignedString([]byte(jwtSecret))
	require.NoError(t, err)

	// Validate the token
	resultClaims, err := decodeAndValidateToken(tokenString, jwtSecret)

	// Assert
	assert.NoError(t, err, "Token with kid should be validated successfully")
	assert.NotNil(t, resultClaims)
	assert.Equal(t, "test-user", resultClaims.Sub)
}

// TestSupabaseJWTValidation tests the validation of Supabase JWT tokens
func TestSupabaseJWTValidation(t *testing.T) {
	// Create a test JWT secret (this would be the Supabase JWT secret)
	jwtSecret := "your-supabase-jwt-secret"

	// Create a test JWT token with Supabase-like structure
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		Sub:   "98bb060d-ad5b-40fe-a7c8-9c8748f09805",
		Email: stringPtr("dylan@lambgoat.com"),
		Role:  stringPtr("authenticated"),
		Aud:   stringPtr("authenticated"),
		Iss:   stringPtr("https://fpuueievvvxbgbqtkjyd.supabase.co/auth/v1"),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})

	// Add a Key ID (kid) to the token header, which is common in Supabase tokens
	token.Header["kid"] = "KnzECV5i9h/u4BMW"

	// Sign the token
	tokenString, err := token.SignedString([]byte(jwtSecret))
	require.NoError(t, err)

	// Create a test request with the token
	req := httptest.NewRequest("GET", "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	// Verify the token
	claims, err := VerifyToken(req, jwtSecret)
	
	// Assert that the token is valid
	assert.NoError(t, err, "Token validation should succeed")
	assert.NotNil(t, claims, "Claims should not be nil")
	assert.Equal(t, "98bb060d-ad5b-40fe-a7c8-9c8748f09805", claims.Sub, "User ID should match")
	assert.Equal(t, "dylan@lambgoat.com", *claims.Email, "Email should match")
	assert.Equal(t, "authenticated", *claims.Role, "Role should match")
}

// TestSupabaseJWTValidationWithRealToken tests validation with a structure similar to real Supabase tokens
func TestSupabaseJWTValidationWithRealToken(t *testing.T) {
	// This test simulates a more realistic Supabase token structure
	// The secret format is critical for Supabase JWT validation

	// Create a test JWT secret (this would be the Supabase JWT secret)
	// Note: Supabase JWT secrets are base64 encoded strings
	jwtSecret := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// Create claims similar to what Supabase would generate
	claims := &Claims{
		Sub:   "98bb060d-ad5b-40fe-a7c8-9c8748f09805",
		Email: stringPtr("dylan@lambgoat.com"),
		Role:  stringPtr("authenticated"),
		Aud:   stringPtr("authenticated"),
		Iss:   stringPtr("https://fpuueievvvxbgbqtkjyd.supabase.co/auth/v1"),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	// Create a token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	
	// Add a Key ID (kid) to the token header
	token.Header["kid"] = "KnzECV5i9h/u4BMW"
	
	// Sign the token
	tokenString, err := token.SignedString([]byte(jwtSecret))
	require.NoError(t, err)

	// Create a test request with the token
	req := httptest.NewRequest("GET", "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	// Verify the token
	resultClaims, err := VerifyToken(req, jwtSecret)
	
	// Assert that the token is valid
	assert.NoError(t, err, "Token validation should succeed")
	assert.NotNil(t, resultClaims, "Claims should not be nil")
	assert.Equal(t, claims.Sub, resultClaims.Sub, "User ID should match")
	assert.Equal(t, *claims.Email, *resultClaims.Email, "Email should match")
	assert.Equal(t, *claims.Role, *resultClaims.Role, "Role should match")
}

// Helper function to create a string pointer
func stringPtr(s string) *string {
	return &s
}

// Helper function to create a test JWT token with Supabase-like structure
func createSupabaseTestJWT(t *testing.T, secret string, expiration time.Duration) string {
	// Create claims
	role := "authenticated"
	email := "test@example.com"
	aud := "authenticated"
	iss := "https://example.supabase.co/auth/v1"
	
	claims := &Claims{
		Sub:   "test-user-id",
		Role:  &role,
		Email: &email,
		Aud:   &aud,
		Iss:   &iss,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
		},
	}
	
	// Create token with kid header
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "test-kid"
	
	// Sign token
	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	
	return tokenString
} 