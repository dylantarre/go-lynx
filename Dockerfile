FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies with verbose output
RUN go mod download -x

# Copy the source code
COPY . .

# Build the application with proper flags and verbose output
RUN CGO_ENABLED=0 GOOS=linux go build -v -o /go-lynx ./cmd/server

# Create a minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /go-lynx /go-lynx

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
