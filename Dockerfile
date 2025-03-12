FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /go-cassowary ./cmd/server

# Create the final image
FROM alpine:latest

# Install runtime dependencies for audio
RUN apk add --no-cache alsa-utils alsa-lib alsa-lib-dev pulseaudio

# Set the working directory
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /go-cassowary /app/go-cassowary

# Copy music files if they exist in the repository
COPY ./music /music

# Expose the port
EXPOSE 3500

# Run the application
CMD ["/app/go-cassowary"]
