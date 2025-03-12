FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application with proper flags
RUN CGO_ENABLED=0 GOOS=linux go build -o /go-lynx ./cmd/server

# Create a minimal runtime image
FROM alpine:latest

WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /go-lynx /go-lynx

# Create music directory
RUN mkdir -p /music && chmod 777 /music

# Expose the port
EXPOSE 3500

# Run the binary
CMD ["/go-lynx"]
