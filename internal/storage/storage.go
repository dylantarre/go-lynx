package storage

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Storage defines the interface for music file storage
type Storage interface {
	// ListTracks returns a list of all track IDs in storage
	ListTracks(ctx context.Context) ([]string, error)
	// GetTrack returns a reader for the track with the given ID
	GetTrack(ctx context.Context, id string) (io.ReadCloser, error)
	// GetTrackRange returns a reader for a specific byte range of the track
	GetTrackRange(ctx context.Context, id string, start, end int64) (io.ReadCloser, error)
	// TrackExists checks if a track exists in storage
	TrackExists(ctx context.Context, id string) (bool, error)
}

// R2Storage implements the Storage interface using Cloudflare R2
type R2Storage struct {
	client *s3.Client
	bucket string
}

// NewR2Storage creates a new R2Storage instance
func NewR2Storage(endpoint, accessKeyID, secretAccessKey, bucket string) (*R2Storage, error) {
	r2Resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL: endpoint,
		}, nil
	})

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithEndpointResolverWithOptions(r2Resolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
		config.WithRegion("auto"),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	client := s3.NewFromConfig(cfg)

	return &R2Storage{
		client: client,
		bucket: bucket,
	}, nil
}

// ListTracks returns a list of all track IDs in storage
func (r *R2Storage) ListTracks(ctx context.Context) ([]string, error) {
	var tracks []string
	var continuationToken *string

	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            aws.String(r.bucket),
			ContinuationToken: continuationToken,
		}

		output, err := r.client.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		for _, obj := range output.Contents {
			// Only include music files
			if isMusicFile(*obj.Key) {
				tracks = append(tracks, *obj.Key)
			}
		}

		if output.IsTruncated == nil || !*output.IsTruncated {
			break
		}
		continuationToken = output.NextContinuationToken
	}

	return tracks, nil
}

// GetTrack returns a reader for the track with the given ID
func (r *R2Storage) GetTrack(ctx context.Context, id string) (io.ReadCloser, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(id),
	}

	output, err := r.client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}

	return output.Body, nil
}

// GetTrackRange returns a reader for a specific byte range of the track
func (r *R2Storage) GetTrackRange(ctx context.Context, id string, start, end int64) (io.ReadCloser, error) {
	rangeStr := fmt.Sprintf("bytes=%d-%d", start, end)
	input := &s3.GetObjectInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(id),
		Range:  aws.String(rangeStr),
	}

	output, err := r.client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get object range: %w", err)
	}

	return output.Body, nil
}

// TrackExists checks if a track exists in storage
func (r *R2Storage) TrackExists(ctx context.Context, id string) (bool, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(id),
	}

	_, err := r.client.HeadObject(ctx, input)
	if err != nil {
		// If the error is a NotFound error, return false without an error
		if strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "404") {
			return false, nil
		}
		return false, fmt.Errorf("failed to check if object exists: %w", err)
	}

	return true, nil
}

// isMusicFile checks if a file is a music file based on its extension
func isMusicFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".mp3", ".m4a", ".flac", ".wav", ".ogg", ".aac":
		return true
	default:
		return false
	}
} 