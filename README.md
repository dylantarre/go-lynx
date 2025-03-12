# lynx.fm Music Server

A music streaming server written in Go that provides endpoints for streaming music tracks with JWT authentication via Supabase.

## Features

- Health check endpoint
- Random track selection
- Track streaming with support for range requests
- Track prefetching
- User authentication via Supabase JWT tokens
- Docker support for containerized deployment

## Requirements

- Go 1.21 or higher
- Supabase project with JWT authentication
- Music files in MP3 format

## Environment Variables

The following environment variables are required:

- `MUSIC_DIR`: Directory containing the music files (default: `/music`)
- `SUPABASE_JWT_SECRET`: Secret for validating JWT tokens from Supabase
- `PORT`: Port on which the server listens (default: `3500`)
- `LOG_LEVEL`: Logging level (default: `info`)

## API Endpoints

### Public Endpoints

- `GET /health`: Health check endpoint
- `GET /random`: Get a random track ID

### Protected Endpoints (require authentication)

- `GET /tracks/{id}`: Stream a track by ID
- `POST /prefetch`: Prefetch tracks
- `GET /me`: Get user information

## Authentication

The server uses JWT tokens from Supabase for authentication. The token should be provided in the `Authorization` header as a Bearer token:

```
Authorization: Bearer <token>
```

For CLI compatibility, you can also use the `apikey` header:

```
apikey: <api_key>
```

## Docker

To build and run the server using Docker:

```bash
docker build -t go-lynx .
docker run -p 3500:3500 -e SUPABASE_JWT_SECRET=your_secret -v /path/to/music:/music go-lynx
```

Or using Docker Compose:

```bash
SUPABASE_JWT_SECRET=your_secret docker-compose up -d
```

## Development

To run the server locally:

```bash
# Install dependencies
go mod download

# Run the server
go run ./cmd/server/main.go
