FROM golang:1.21 AS builder

WORKDIR /src

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o /app/go-lynx ./cmd/server

# Create a minimal runtime image
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /app/go-lynx /go-lynx

# Create music directory
RUN mkdir -p /music && chmod 777 /music

# Set default environment variables
ENV MUSIC_DIR=/music \
    PORT=3500 \
    LOG_LEVEL=debug

# Expose the port
EXPOSE 3500

# Run the binary
CMD ["/go-lynx"]
