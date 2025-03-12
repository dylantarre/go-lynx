package auth

import (
	"errors"
	"fmt"
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
		return decodeAndValidateToken(tokenString, jwtSecret)
	}

	// Check for apikey header (for CLI compatibility)
	apiKey := r.Header.Get("apikey")
	if apiKey != "" {
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
		// Validate the algorithm
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Check if the token is valid
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token: claims validation failed")
}

// ExtractUserID extracts the user ID from claims
func ExtractUserID(claims *Claims) string {
	return claims.Sub
}
