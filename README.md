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

## Connecting to the API

### Getting Started

1. **Set up Supabase Authentication**:
   - Create a Supabase project at [https://supabase.com](https://supabase.com)
   - Configure authentication methods (email/password, social providers, etc.)
   - Obtain your JWT secret from the Supabase dashboard

2. **Obtain a JWT Token**:
   - Use Supabase client libraries to authenticate users
   - Store the returned JWT token securely

### API Connection Examples

#### Using cURL

```bash
# Health check
curl -X GET https://go.lynx.fm/health

# Get a random track ID
curl -X GET https://go.lynx.fm/random

# Stream a track (requires authentication)
curl -X GET https://go.lynx.fm/tracks/track_id_here \
  -H "Authorization: Bearer your_jwt_token_here"

# Prefetch tracks (requires authentication)
curl -X POST https://go.lynx.fm/prefetch \
  -H "Authorization: Bearer your_jwt_token_here" \
  -H "Content-Type: application/json" \
  -d '{"tracks": ["track_id_1", "track_id_2"]}'

# Get user information (requires authentication)
curl -X GET https://go.lynx.fm/me \
  -H "Authorization: Bearer your_jwt_token_here"
```

#### Using JavaScript (Fetch API)

```javascript
// Health check
fetch('https://go.lynx.fm/health')
  .then(response => response.json())
  .then(data => console.log(data));

// Get a random track with authentication
const token = 'your_jwt_token_here';
fetch('https://go.lynx.fm/random', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
})
  .then(response => response.json())
  .then(data => console.log(data));

// Stream a track (typically used in audio elements)
const audioElement = document.createElement('audio');
audioElement.src = `https://go.lynx.fm/tracks/track_id_here`;
audioElement.setAttribute('type', 'audio/mpeg');

// Add authentication header to requests
fetch(audioElement.src, {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

#### Using Go Client

```go
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	// Set your JWT token
	token := "your_jwt_token_here"
	
	// Create a new request
	req, err := http.NewRequest("GET", "https://go.lynx.fm/tracks/track_id_here", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	
	// Add authorization header
	req.Header.Add("Authorization", "Bearer "+token)
	
	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()
	
	// Process the response
	// For streaming to a file:
	file, err := os.Create("downloaded_track.mp3")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()
	
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	
	fmt.Println("Track downloaded successfully")
}
```

#### Using Python (Requests)

```python
import requests

# Set your JWT token
token = "your_jwt_token_here"
headers = {"Authorization": f"Bearer {token}"}

# Health check
response = requests.get("https://go.lynx.fm/health")
print(response.json())

# Get a random track
response = requests.get("https://go.lynx.fm/random", headers=headers)
print(response.json())

# Stream a track
response = requests.get(
    "https://go.lynx.fm/tracks/track_id_here", 
    headers=headers,
    stream=True  # Important for streaming large files
)

# Save the streamed track
if response.status_code == 200:
    with open("downloaded_track.mp3", "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    print("Track downloaded successfully")
else:
    print(f"Error: {response.status_code}")
```

### Integration with Supabase

To integrate with Supabase for authentication:

1. **Frontend Integration**:
   ```javascript
   import { createClient } from '@supabase/supabase-js'

   const supabaseUrl = 'https://your-project.supabase.co'
   const supabaseKey = 'your-anon-key'
   const supabase = createClient(supabaseUrl, supabaseKey)

   // Sign in user
   const { data, error } = await supabase.auth.signInWithPassword({
     email: 'user@example.com',
     password: 'password123'
   })

   // Get the JWT token
   const token = data.session.access_token

   // Use this token for API requests to go-lynx
   ```

2. **Server Configuration**:
   - Set the `SUPABASE_JWT_SECRET` environment variable to your Supabase JWT secret
   - The server will validate incoming JWT tokens against this secret

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
