package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestMiddleware_WithValidJWT tests the middleware with a valid JWT token
func TestMiddleware_WithValidJWT(t *testing.T) {
	// Create a valid JWT token for testing
	secret := "test_jwt_secret"
	token := createTestJWT(t, secret, time.Hour)
	
	// Create a test request with the token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	
	// Create a test response recorder
	rr := httptest.NewRecorder()
	
	// Create a test handler that checks for claims in the context
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := GetClaims(r.Context())
		assert.True(t, ok)
		assert.NotNil(t, claims)
		assert.Equal(t, "test-user", claims.Sub)
		w.WriteHeader(http.StatusOK)
	})
	
	// Create the middleware
	middleware := Middleware(secret)
	
	// Apply the middleware to the test handler
	handler := middleware(testHandler)
	
	// Serve the request
	handler.ServeHTTP(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestMiddleware_WithInvalidJWT tests the middleware with an invalid JWT token
func TestMiddleware_WithInvalidJWT(t *testing.T) {
	// Create an invalid JWT token (wrong secret)
	secret1 := "test_jwt_secret"
	token := createTestJWT(t, secret1, time.Hour)
	
	// Use a different secret for validation
	secret2 := "different_secret"
	
	// Create a test request with the token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	
	// Create a test response recorder
	rr := httptest.NewRecorder()
	
	// Create a test handler that should not be called
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called with invalid token")
	})
	
	// Create the middleware with the different secret
	middleware := Middleware(secret2)
	
	// Apply the middleware to the test handler
	handler := middleware(testHandler)
	
	// Serve the request
	handler.ServeHTTP(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	
	// Check response body
	var response map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response, "error")
	assert.Contains(t, response, "detail")
}

// TestMiddleware_WithExpiredJWT tests the middleware with an expired JWT token
func TestMiddleware_WithExpiredJWT(t *testing.T) {
	// Create an expired JWT token
	secret := "test_jwt_secret"
	token := createTestJWT(t, secret, -time.Hour) // Expired 1 hour ago
	
	// Create a test request with the token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	
	// Create a test response recorder
	rr := httptest.NewRecorder()
	
	// Create a test handler that should not be called
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called with expired token")
	})
	
	// Create the middleware
	middleware := Middleware(secret)
	
	// Apply the middleware to the test handler
	handler := middleware(testHandler)
	
	// Serve the request
	handler.ServeHTTP(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	
	// Check response body
	var response map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "Token has expired")
}

// TestMiddleware_WithAPIKey tests the middleware with an API key
func TestMiddleware_WithAPIKey(t *testing.T) {
	// Create a test request with an API key
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("apikey", "test-api-key")
	
	// Create a test response recorder
	rr := httptest.NewRecorder()
	
	// Create a test handler that checks for claims in the context
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := GetClaims(r.Context())
		assert.True(t, ok)
		assert.NotNil(t, claims)
		assert.Equal(t, "anon-user", claims.Sub)
		assert.NotNil(t, claims.Role)
		assert.Equal(t, "anon", *claims.Role)
		w.WriteHeader(http.StatusOK)
	})
	
	// Create the middleware
	middleware := Middleware("any_secret")
	
	// Apply the middleware to the test handler
	handler := middleware(testHandler)
	
	// Serve the request
	handler.ServeHTTP(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestMiddleware_WithNoAuth tests the middleware with no authentication
func TestMiddleware_WithNoAuth(t *testing.T) {
	// Create a test request with no authentication
	req := httptest.NewRequest("GET", "/test", nil)
	
	// Create a test response recorder
	rr := httptest.NewRecorder()
	
	// Create a test handler that should not be called
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called with no authentication")
	})
	
	// Create the middleware
	middleware := Middleware("any_secret")
	
	// Apply the middleware to the test handler
	handler := middleware(testHandler)
	
	// Serve the request
	handler.ServeHTTP(rr, req)
	
	// Assert
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	
	// Check response body
	var response map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "No authentication provided")
}

// TestMiddleware_PublicEndpoint tests the middleware with a public endpoint
func TestMiddleware_PublicEndpoint(t *testing.T) {
	// Create a test request for a public endpoint
	req := httptest.NewRequest("GET", "/health", nil)
	
	// Create a test response recorder
	rr := httptest.NewRecorder()
	
	// Create a test handler that should be called for public endpoints
	handlerCalled := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})
	
	// Create the middleware
	middleware := Middleware("any_secret")
	
	// Apply the middleware to the test handler
	handler := middleware(testHandler)
	
	// Serve the request
	handler.ServeHTTP(rr, req)
	
	// Assert
	assert.True(t, handlerCalled, "Handler should be called for public endpoint")
	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestGetClaims tests retrieving claims from context
func TestGetClaims(t *testing.T) {
	// Create test claims
	testClaims := &Claims{
		Sub: "test-user",
	}
	
	// Create a context with the claims
	ctx := context.WithValue(context.Background(), ContextKey, testClaims)
	
	// Get the claims from the context
	claims, ok := GetClaims(ctx)
	
	// Assert
	assert.True(t, ok)
	assert.NotNil(t, claims)
	assert.Equal(t, "test-user", claims.Sub)
	
	// Test with a context that doesn't have claims
	emptyCtx := context.Background()
	emptyClaims, ok := GetClaims(emptyCtx)
	
	// Assert
	assert.False(t, ok)
	assert.Nil(t, emptyClaims)
} 