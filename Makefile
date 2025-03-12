.PHONY: build test test-unit test-integration run clean

# Default target
all: build

# Build the application
build:
	go build -o go-lynx ./cmd/server

# Run all tests
test: test-unit test-integration

# Run unit tests
test-unit:
	go test -v ./internal/auth/...
	go test -v ./internal/handlers/...

# Run integration tests
test-integration:
	go test -v ./internal/...

# Run the application
run: build
	./go-lynx

# Clean build artifacts
clean:
	rm -f go-lynx

# Build for Linux
build-linux:
	GOOS=linux GOARCH=amd64 go build -o go-lynx ./cmd/server

# Run tests with coverage
test-coverage:
	go test -coverprofile=coverage.out ./internal/...
	go tool cover -html=coverage.out

# Lint the code
lint:
	golangci-lint run

# Format the code
fmt:
	go fmt ./...

# Install dependencies
deps:
	go mod download

# Help target
help:
	@echo "Available targets:"
	@echo "  build           - Build the application"
	@echo "  test            - Run all tests"
	@echo "  test-unit       - Run unit tests"
	@echo "  test-integration - Run integration tests"
	@echo "  test-coverage   - Run tests with coverage report"
	@echo "  run             - Build and run the application"
	@echo "  clean           - Remove build artifacts"
	@echo "  build-linux     - Build for Linux"
	@echo "  lint            - Lint the code"
	@echo "  fmt             - Format the code"
	@echo "  deps            - Install dependencies" 