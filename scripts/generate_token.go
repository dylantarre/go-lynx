package main

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// Get the secret from environment variable
	secret := os.Getenv("SUPABASE_JWT_SECRET")
	if secret == "" {
		fmt.Println("Error: SUPABASE_JWT_SECRET environment variable not set")
		os.Exit(1)
	}

	// Create the claims
	claims := jwt.MapClaims{
		"aud":     "authenticated",
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // 24 hour expiration
		"iat":     time.Now().Unix(),
		"iss":     "https://fpuueievvvxbgbqtkjyd.supabase.co/auth/v1",
		"sub":     "98bb060d-ad5b-40fe-a7c8-9c8748f09805",
		"email":   "dylan@lambgoat.com",
		"role":    "authenticated",
		"session_id": "test-session",
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		fmt.Printf("Error signing token: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(tokenString)
} 