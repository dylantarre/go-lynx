FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /

# Copy the pre-built binary
COPY go-lynx /go-lynx

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
