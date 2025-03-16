// This file contains the implementation of JWT token verification and validation functions used in the application.
// It includes the definition of the Claims structure, functions to verify tokens from HTTP requests, 
// and helper functions for debugging and extracting user information from the claims.

package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// User represents an authenticated user
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// Claims represents the JWT claims
type Claims struct {
	jwt.RegisteredClaims
	Sub   string  `json:"sub"`
	Email *string `json:"email"`
	Role  *string `json:"role"`
	Aud   *string `json:"aud"`
	Iss   *string `json:"iss"`
}

// contextKey is a custom type for context keys
type contextKey string

const (
	// UserContextKey is the key used to store the user in the context
	UserContextKey contextKey = "user"
)

// Middleware handles authentication using JWT tokens
func Middleware(jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header is required", http.StatusUnauthorized)
				return
			}

			// Check if the header starts with "Bearer "
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			// Extract the token
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			// Parse and validate the token
			token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
				// Validate the signing method
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}

				// Return the secret key
				return []byte(jwtSecret), nil
			})

			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Get the claims
			claims, ok := token.Claims.(*Claims)
			if !ok || !token.Valid {
				http.Error(w, "Invalid token claims", http.StatusUnauthorized)
				return
			}

			// Create a user from the claims
			user := &User{
				ID:    claims.Sub,
				Email: stringValue(claims.Email),
				Role:  stringValue(claims.Role),
			}

			// Add the user to the context
			ctx := context.WithValue(r.Context(), UserContextKey, user)

			// Call the next handler with the updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserFromContext retrieves the user from the context
func GetUserFromContext(ctx context.Context) *User {
	user, ok := ctx.Value(UserContextKey).(*User)
	if !ok {
		return nil
	}
	return user
}

// VerifyToken verifies a JWT token from the Authorization header
func VerifyToken(r *http.Request, jwtSecret string) (*Claims, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, false
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, false
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, false
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, true
	}

	return nil, false
}

// GetAnonymousClaims returns claims for an anonymous user
func GetAnonymousClaims() *Claims {
	email := ""
	role := "anon"
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "anon-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
		Email: &email,
		Role:  &role,
	}
}

// Helper function to safely get string value from pointer
func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
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

	// Log the token header and claims for debugging
	log.Printf("Token header: %v", token.Header)
	
	// Check for kid (Key ID) in the header, which is common in Supabase tokens
	if kid, ok := token.Header["kid"].(string); ok {
		log.Printf("Token has Key ID (kid): %s", kid)
	}
	
	if claims, ok := token.Claims.(*Claims); ok {
		log.Printf("Token claims - Sub: %s, Email: %v, Role: %v, Aud: %v, Iss: %v", 
			claims.Subject, 
			claims.Email, 
			claims.Role,
			claims.Aud,
			claims.Iss)
		
		if claims.ExpiresAt != nil {
			log.Printf("Token expires at: %v", claims.ExpiresAt.Time)
		}
	}

	// Determine the signing method from the token header
	alg, ok := token.Header["alg"].(string)
	if !ok {
		log.Printf("Token header missing 'alg' claim")
		return nil, errors.New("token header missing algorithm")
	}

	// Log JWT secret debug info
	secretInfo := DebugJWTSecret(jwtSecret)
	log.Printf("JWT Secret Info: %+v", secretInfo)

	// IMPORTANT: Supabase JWT validation
	// Supabase uses HS256 algorithm with a specific secret format
	if alg != "HS256" {
		log.Printf("Unexpected algorithm: %s. Supabase typically uses HS256", alg)
		return nil, fmt.Errorf("unexpected signing method: %v", alg)
	}

	// Try multiple approaches for the secret
	var validatedToken *jwt.Token
	var validationErr error

	// For Supabase, we need to base64 decode the secret
	secretKey := []byte(strings.TrimSpace(jwtSecret))
	log.Printf("Using JWT secret (length: %d)", len(secretKey))
	
	validatedToken, err = jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	
	if err != nil {
		log.Printf("JWT validation failed: %v", err)
		validationErr = err
	} else {
		log.Printf("JWT validation successful!")
	}

	// If all validation attempts failed, return the error
	if validatedToken == nil || !validatedToken.Valid {
		if validationErr != nil {
			log.Printf("JWT validation failed: %v", validationErr)
			return nil, fmt.Errorf("invalid token: %w", validationErr)
		}
		log.Printf("JWT validation failed: token is invalid")
		return nil, errors.New("invalid token: validation failed")
	}

	// Extract and return the claims
	if claims, ok := validatedToken.Claims.(*Claims); ok {
		log.Printf("JWT validation successful for user: %s", claims.Subject)
		return claims, nil
	}

	log.Printf("JWT claims extraction failed")
	return nil, errors.New("invalid token: claims extraction failed")
}

// ExtractUserID extracts the user ID from claims
func ExtractUserID(claims *Claims) string {
	return claims.Subject
}

// Helper function for string truncation
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// DebugJWTSecret returns information about the JWT secret format without exposing the actual secret
func DebugJWTSecret(jwtSecret string) map[string]interface{} {
	info := make(map[string]interface{})
	
	// Basic information
	info["length"] = len(jwtSecret)
	info["format"] = "unknown"
	
	// Check if it's a base64 encoded string
	if len(jwtSecret) % 4 == 0 {
		info["possible_encoding"] = "might be base64 (length is multiple of 4)"
	}
	
	// Check for common prefixes in JWT secrets
	if strings.HasPrefix(jwtSecret, "ey") {
		info["note"] = "starts with 'ey', which is common for JWT tokens, not secrets"
	}
	
	// Check character set
	hasSpecial := false
	hasAlpha := false
	hasNumeric := false
	
	for _, c := range jwtSecret {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasAlpha = true
		} else if c >= '0' && c <= '9' {
			hasNumeric = true
		} else {
			hasSpecial = true
		}
	}
	
	charTypes := []string{}
	if hasAlpha {
		charTypes = append(charTypes, "alphabetic")
	}
	if hasNumeric {
		charTypes = append(charTypes, "numeric")
	}
	if hasSpecial {
		charTypes = append(charTypes, "special")
	}
	
	info["character_types"] = charTypes
	
	// First few characters (safely)
	if len(jwtSecret) > 3 {
		info["starts_with"] = jwtSecret[:3] + "..."
	}
	
	return info
}

// TryValidateWithMultipleSecrets attempts to validate a JWT token with multiple secret formats
// This is useful for debugging JWT validation issues
func TryValidateWithMultipleSecrets(tokenString string, jwtSecret string) map[string]interface{} {
	results := make(map[string]interface{})
	
	// First, try to parse the token without validation to inspect its header
	parser := &jwt.Parser{}
	token, _, err := parser.ParseUnverified(tokenString, &Claims{})
	if err != nil {
		results["parse_error"] = err.Error()
		return results
	}
	
	// Log the token header
	results["header"] = token.Header
	
	// Determine the signing method from the token header
	alg, ok := token.Header["alg"].(string)
	if !ok {
		results["error"] = "Token header missing algorithm"
		return results
	}
	
	results["algorithm"] = alg
	
	// Try multiple approaches for the secret
	attempts := map[string][]byte{
		"original": []byte(jwtSecret),
		"trimmed": []byte(strings.TrimSpace(jwtSecret)),
	}
	
	validationAttempts := make(map[string]interface{})
	
	for name, secret := range attempts {
		// Try to validate with this secret
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return secret, nil
		})
		
		result := map[string]interface{}{
			"success": err == nil && token != nil && token.Valid,
			"error":   "",
		}
		
		if err != nil {
			result["error"] = err.Error()
		}
		
		if token != nil {
			result["valid"] = token.Valid
		}
		
		// Add to both the top level results and the validation_attempts map
		results[name] = result
		validationAttempts[name] = result
	}
	
	results["validation_attempts"] = validationAttempts
	return results
}

// CreateToken creates a JWT token with the given claims and secret
func CreateToken(claims *Claims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
