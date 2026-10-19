package resolver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var (
	ErrInvalidReference = errors.New("invalid container image reference")
	ErrNotFound         = errors.New("image digest not found in registry")
	ErrRevoked          = errors.New("image digest is revoked")
)

type CacheEntry struct {
	Digest    string
	ExpiresAt time.Time
}

type Resolver struct {
	mu           sync.RWMutex
	cache        map[string]CacheEntry
	revocations  map[string]struct{}
	hostMappings map[string]string
	ttl          time.Duration
}

func NewResolver(ttl time.Duration) *Resolver {
	r := &Resolver{
		cache:        make(map[string]CacheEntry),
		revocations:  make(map[string]struct{}),
		hostMappings: make(map[string]string),
		ttl:          ttl,
	}

	if envMap := os.Getenv("AEGISCHAIN_REGISTRY_MAP"); envMap != "" {
		for _, pair := range strings.Split(envMap, ",") {
			parts := strings.Split(pair, "=")
			if len(parts) == 2 {
				r.hostMappings[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	return r
}

// AddHostMapping configures in-memory host translation (e.g. localhost:5001 -> aegis-registry:5000).
func (r *Resolver) AddHostMapping(from, to string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hostMappings[from] = to
}

// MapImageRef returns the network-accessible image reference based on configured mappings.
func (r *Resolver) MapImageRef(imageRef string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for from, to := range r.hostMappings {
		if strings.HasPrefix(imageRef, from) {
			return strings.Replace(imageRef, from, to, 1)
		}
	}
	return imageRef
}

// RevokeDigest immediately invalidates any cache and flags the digest as untrusted.
func (r *Resolver) RevokeDigest(digest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	clean := strings.TrimPrefix(digest, "sha256:")
	r.revocations[digest] = struct{}{}
	r.revocations[clean] = struct{}{}
	r.revocations["sha256:"+clean] = struct{}{}
	// Invalidate cache
	for k, v := range r.cache {
		if strings.Contains(v.Digest, clean) {
			delete(r.cache, k)
		}
	}
}

// IsRevoked returns true if the digest is in the revocation registry.
func (r *Resolver) IsRevoked(digest string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	clean := strings.TrimPrefix(digest, "sha256:")
	if _, revoked := r.revocations[digest]; revoked {
		return true
	}
	if _, revoked := r.revocations[clean]; revoked {
		return true
	}
	if _, revoked := r.revocations["sha256:"+clean]; revoked {
		return true
	}
	return false
}

// Resolve pins an image reference (tag or digest) to an immutable SHA-256 digest.
func (r *Resolver) Resolve(ctx context.Context, imageRef string) (string, error) {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return "", ErrInvalidReference
	}

	// Apply host mapping if present
	targetRef := r.MapImageRef(imageRef)

	// Check if already an immutable digest reference
	if strings.Contains(targetRef, "@sha256:") {
		parts := strings.Split(targetRef, "@")
		digest := parts[1]
		r.mu.RLock()
		if _, revoked := r.revocations[digest]; revoked {
			r.mu.RUnlock()
			return "", ErrRevoked
		}
		r.mu.RUnlock()
		return digest, nil
	}

	// Check cache
	r.mu.RLock()
	if entry, ok := r.cache[imageRef]; ok {
		if time.Now().Before(entry.ExpiresAt) {
			if _, revoked := r.revocations[entry.Digest]; revoked {
				r.mu.RUnlock()
				return "", ErrRevoked
			}
			r.mu.RUnlock()
			return entry.Digest, nil
		}
	}
	r.mu.RUnlock()

	var opts []name.Option
	if strings.HasPrefix(targetRef, "localhost:") || strings.HasPrefix(targetRef, "127.0.0.1:") || strings.Contains(targetRef, "aegis-registry:") || strings.Contains(targetRef, ":5000") || strings.Contains(targetRef, ":5001") {
		opts = append(opts, name.Insecure)
	}

	// Parse reference with go-containerregistry
	ref, err := name.ParseReference(targetRef, opts...)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidReference, err)
	}

	desc, err := remote.Head(ref, remote.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNotFound, err)
	}

	digest := desc.Digest.String()

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, revoked := r.revocations[digest]; revoked {
		return "", ErrRevoked
	}

	if r.ttl > 0 {
		r.cache[imageRef] = CacheEntry{
			Digest:    digest,
			ExpiresAt: time.Now().Add(r.ttl),
		}
	}

	return digest, nil
}
