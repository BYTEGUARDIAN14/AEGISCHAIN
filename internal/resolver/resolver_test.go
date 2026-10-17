package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestResolverDirectDigest(t *testing.T) {
	r := NewResolver(10 * time.Minute)
	ctx := context.Background()

	ref := "registry.example.com/app@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	digest, err := r.Resolve(ctx, ref)
	assert.NoError(t, err)
	assert.Equal(t, "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", digest)
}

func TestResolverRevocation(t *testing.T) {
	r := NewResolver(10 * time.Minute)
	ctx := context.Background()

	targetDigest := "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	ref := "registry.example.com/app@" + targetDigest

	// Should succeed initially
	d, err := r.Resolve(ctx, ref)
	assert.NoError(t, err)
	assert.Equal(t, targetDigest, d)

	// Revoke digest
	r.RevokeDigest(targetDigest)

	// Subsequent resolve must fail with ErrRevoked
	_, err = r.Resolve(ctx, ref)
	assert.ErrorIs(t, err, ErrRevoked)
}

func TestResolverInvalidReference(t *testing.T) {
	r := NewResolver(10 * time.Minute)
	ctx := context.Background()

	_, err := r.Resolve(ctx, "")
	assert.ErrorIs(t, err, ErrInvalidReference)
}
