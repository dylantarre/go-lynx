FROM golang:1.21-bullseye AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application for linux/amd64
RUN GOOS=linux GOARCH=amd64 go build -o go-lynx cmd/server/main.go

# Create the final image
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /

# Copy the pre-built binary from the builder stage
COPY --from=builder /app/go-lynx /go-lynx

# Create necessary directories
RUN mkdir -p /music && chmod 777 /music && \
    mkdir -p /certs && chmod 700 /certs

# Set default environment variables
ENV MUSIC_DIR=/music \
    PORT=3501 \
    LOG_LEVEL=debug \
    TLS_CERT_FILE=/certs/cert.pem \
    TLS_KEY_FILE=/certs/key.pem

# Expose the port
EXPOSE 3501

# Run the binary
CMD ["/go-lynx"]
