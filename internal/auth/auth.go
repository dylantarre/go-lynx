package auth

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims structure for Supabase authentication
type Claims struct {
	Sub   string  `json:"sub"`
	Email *string `json:"email,omitempty"`
	Role  *string `json:"role,omitempty"`
	jwt.RegisteredClaims
}

// VerifyToken verifies a JWT token from the Authorization header
func VerifyToken(r *http.Request, jwtSecret string) (*Claims, error) {
	// Check for Authorization header (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		log.Printf("Attempting to validate JWT token: %s...", tokenString[:min(30, len(tokenString))])
		log.Printf("JWT secret length: %d", len(jwtSecret))
		return decodeAndValidateToken(tokenString, jwtSecret)
	}

	// Check for apikey header (for CLI compatibility)
	apiKey := r.Header.Get("apikey")
	if apiKey != "" {
		log.Printf("Using apikey authentication")
		// Create a simplified anonymous user for API key authentication
		role := "anon"
		return &Claims{
			Sub:   "anon-user",
			Email: nil,
			Role:  &role,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			},
		}, nil
	}

	return nil, errors.New("unauthorized: no valid authentication token found in request")
}

// decodeAndValidateToken decodes and validates a JWT token
func decodeAndValidateToken(tokenString string, jwtSecret string) (*Claims, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Log the token header for debugging
		log.Printf("Token header: %v", token.Header)
		
		// Validate the algorithm
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Printf("Unexpected signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		log.Printf("JWT validation error: %v", err)
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Check if the token is valid
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		log.Printf("JWT validation successful for user: %s", claims.Sub)
		return claims, nil
	}

	log.Printf("JWT claims validation failed")
	return nil, errors.New("invalid token: claims validation failed")
}

// ExtractUserID extracts the user ID from claims
func ExtractUserID(claims *Claims) string {
	return claims.Sub
}

// Helper function for string truncation
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
