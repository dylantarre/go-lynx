package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dylantarre/go-lynx/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	secret := os.Getenv("SUPABASE_JWT_SECRET")
	if secret == "" {
		log.Fatal("SUPABASE_JWT_SECRET environment variable is required")
	}

	role := "authenticated"
	email := "test@example.com"
	aud := "authenticated"
	iss := "supabase"

	claims := &auth.Claims{
		Sub:   "test-user-123",
		Email: &email,
		Role:  &role,
		Aud:   &aud,
		Iss:   &iss,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token, err := auth.CreateToken(claims, secret)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	fmt.Printf("Generated test token:\n%s\n", token)
} 