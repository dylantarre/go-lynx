package auth

import (
	"encoding/base64"
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
	Aud   *string `json:"aud,omitempty"`    // Audience claim (Supabase URL)
	Iss   *string `json:"iss,omitempty"`    // Issuer claim
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
	// First, try to parse the token without validation to inspect its header
	parser := &jwt.Parser{}
	token, _, err := parser.ParseUnverified(tokenString, &Claims{})
	if err != nil {
		log.Printf("Failed to parse token for inspection: %v", err)
		return nil, fmt.Errorf("invalid token format: %w", err)
	}

	// Log the token header for debugging
	log.Printf("Token header: %v", token.Header)
	
	// Determine the signing method from the token header
	alg, ok := token.Header["alg"].(string)
	if !ok {
		log.Printf("Token header missing 'alg' claim")
		return nil, errors.New("token header missing algorithm")
	}

	// Now parse and validate the token based on the algorithm
	var validatedToken *jwt.Token
	
	// Try base64 decoding the secret first (Supabase sometimes provides base64-encoded secrets)
	decodedSecret, err := base64.StdEncoding.DecodeString(jwtSecret)
	if err != nil {
		log.Printf("JWT secret is not base64 encoded, using as-is")
		decodedSecret = []byte(jwtSecret)
	} else {
		log.Printf("Successfully decoded base64 JWT secret, length: %d", len(decodedSecret))
	}

	if strings.HasPrefix(alg, "HS") {
		// HMAC-based algorithm (HS256, HS384, HS512)
		log.Printf("Using HMAC validation with algorithm: %s", alg)
		validatedToken, err = jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return decodedSecret, nil
		})
	} else if strings.HasPrefix(alg, "RS") {
		// RSA-based algorithm (RS256, RS384, RS512)
		log.Printf("Using RSA validation with algorithm: %s", alg)
		validatedToken, err = jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// For RSA, the secret should be a public key
			// This is a simplified approach - in production, you'd use proper key management
			return decodedSecret, nil
		})
	} else {
		log.Printf("Unsupported algorithm: %s", alg)
		return nil, fmt.Errorf("unsupported signing method: %s", alg)
	}

	if err != nil {
		log.Printf("JWT validation error: %v", err)
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Check if the token is valid
	if claims, ok := validatedToken.Claims.(*Claims); ok && validatedToken.Valid {
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
