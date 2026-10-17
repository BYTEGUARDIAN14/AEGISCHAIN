package resolver

import (
	"context"
	"errors"
	"fmt"
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
	mu          sync.RWMutex
	cache       map[string]CacheEntry
	revocations map[string]struct{}
	ttl         time.Duration
}

func NewResolver(ttl time.Duration) *Resolver {
	return &Resolver{
		cache:       make(map[string]CacheEntry),
		revocations: make(map[string]struct{}),
		ttl:         ttl,
	}
}

// RevokeDigest immediately invalidates any cache and flags the digest as untrusted.
func (r *Resolver) RevokeDigest(digest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revocations[digest] = struct{}{}
	// Invalidate cache
	for k, v := range r.cache {
		if v.Digest == digest {
			delete(r.cache, k)
		}
	}
}

// Resolve pins an image reference (tag or digest) to an immutable SHA-256 digest.
func (r *Resolver) Resolve(ctx context.Context, imageRef string) (string, error) {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return "", ErrInvalidReference
	}

	// Check if already an immutable digest reference
	if strings.Contains(imageRef, "@sha256:") {
		parts := strings.Split(imageRef, "@")
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

	// Parse reference with go-containerregistry
	ref, err := name.ParseReference(imageRef)
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

	r.cache[imageRef] = CacheEntry{
		Digest:    digest,
		ExpiresAt: time.Now().Add(r.ttl),
	}

	return digest, nil
}
