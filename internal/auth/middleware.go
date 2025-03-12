package auth

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// ClaimsKey is the key used to store claims in the request context
type ClaimsKey string

const (
	// ContextKey is the key used to store claims in the request context
	ContextKey ClaimsKey = "claims"
)

// Middleware creates a middleware that verifies JWT tokens
func Middleware(jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Auth middleware processing request to: %s", r.URL.Path)
			
			// Log headers for debugging (excluding sensitive data)
			for name, values := range r.Header {
				if !strings.EqualFold(name, "Authorization") && !strings.EqualFold(name, "apikey") {
					log.Printf("Header: %s = %v", name, values)
				} else {
					log.Printf("Header: %s = [REDACTED]", name)
				}
			}
			
			claims, err := VerifyToken(r, jwtSecret)
			if err != nil {
				log.Printf("Authentication failed: %v", err)
				
				// Return a JSON error response with more details
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				
				// Extract a more user-friendly error message
				errorMsg := "Unauthorized"
				if strings.Contains(err.Error(), "signing method") {
					errorMsg = "Invalid token signing method"
				} else if strings.Contains(err.Error(), "expired") {
					errorMsg = "Token has expired"
				} else if strings.Contains(err.Error(), "validation") {
					errorMsg = "Token validation failed"
				}
				
				json.NewEncoder(w).Encode(map[string]string{
					"error": errorMsg,
					"detail": "Authentication required",
				})
				return
			}

			// Store claims in request context
			ctx := context.WithValue(r.Context(), ContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims retrieves the claims from the request context
func GetClaims(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ContextKey).(*Claims)
	return claims, ok
}
