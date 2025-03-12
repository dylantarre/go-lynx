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

	// Log the token header and claims for debugging
	log.Printf("Token header: %v", token.Header)
	
	// Check for kid (Key ID) in the header, which is common in Supabase tokens
	if kid, ok := token.Header["kid"].(string); ok {
		log.Printf("Token has Key ID (kid): %s", kid)
	}
	
	if claims, ok := token.Claims.(*Claims); ok {
		log.Printf("Token claims - Sub: %s, Email: %v, Role: %v, Aud: %v, Iss: %v", 
			claims.Sub, 
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

	// Approach 1: Use the secret as-is (most common for Supabase)
	secretKey := []byte(jwtSecret)
	log.Printf("Attempt 1: Using JWT secret as-is (length: %d)", len(secretKey))
	
	validatedToken, err = jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	
	if err != nil {
		log.Printf("Attempt 1 failed: %v", err)
		validationErr = err
		
		// Approach 2: Try with the secret with trailing whitespace trimmed
		trimmedSecret := []byte(strings.TrimSpace(jwtSecret))
		if len(trimmedSecret) != len(secretKey) {
			log.Printf("Attempt 2: Using trimmed JWT secret (length: %d)", len(trimmedSecret))
			
			validatedToken, err = jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return trimmedSecret, nil
			})
			
			if err != nil {
				log.Printf("Attempt 2 failed: %v", err)
			} else {
				log.Printf("Attempt 2 succeeded with trimmed secret!")
			}
		}
	} else {
		log.Printf("Attempt 1 succeeded with original secret!")
	}

	// If all validation attempts failed, return the error
	if validatedToken == nil || !validatedToken.Valid {
		if validationErr != nil {
			log.Printf("All JWT validation attempts failed: %v", validationErr)
			return nil, fmt.Errorf("invalid token: %w", validationErr)
		}
		log.Printf("JWT validation failed: token is invalid")
		return nil, errors.New("invalid token: validation failed")
	}

	// Extract and return the claims
	if claims, ok := validatedToken.Claims.(*Claims); ok {
		log.Printf("JWT validation successful for user: %s", claims.Sub)
		return claims, nil
	}

	log.Printf("JWT claims extraction failed")
	return nil, errors.New("invalid token: claims extraction failed")
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
