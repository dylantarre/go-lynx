FROM golang:1.22-alpine AS builder

# Install build dependencies for CGO (required for SQLite)
RUN apk add --no-cache git gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application with CGO enabled for SQLite
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o main ./cmd/server

# Create final image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Set working directory
WORKDIR /app

# Create data directory for SQLite database
RUN mkdir -p /data && chown -R 1000:1000 /data

# Copy the binary from builder
COPY --from=builder /app/main .

# Expose port
EXPOSE 3500

# Run the application
CMD ["./main"]
