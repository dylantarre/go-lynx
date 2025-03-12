package auth

import (
	"context"
	"net/http"
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
			claims, err := VerifyToken(r, jwtSecret)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
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
