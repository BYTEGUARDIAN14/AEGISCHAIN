package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/byteaegis/aegischain/internal/ledger"
)

func setupTestAPIServer() (*Server, *http.ServeMux) {
	l := ledger.NewLedger()
	sub := ledger.DecisionSubject{
		Image:     "localhost:5001/sample-app:v1.0.0",
		Digest:    "sha256:52242b9363649daf33fecab71ff1a41988547a97a966b5b127ca91c186d3023b",
		Namespace: "prod",
		Workload:  "sample-deployment",
	}
	_, _ = l.Append("dec-test-1", "allow", "enforce", "v1.0.0", sub, nil, 100)

	server := NewServer(l, nil)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)
	return server, mux
}

func TestAPIHealthAndOpenAPI(t *testing.T) {
	_, mux := setupTestAPIServer()

	// /api/v1/healthz
	req := httptest.NewRequest(http.MethodGet, "/api/v1/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"status":"healthy"`)

	// /api/v1/openapi.json
	req = httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"openapi":"3.1.0"`)
}

func TestAPIArtifactsAndProvenanceGraph(t *testing.T) {
	_, mux := setupTestAPIServer()

	// /api/v1/artifacts
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var artifacts []ArtifactSummary
	err := json.Unmarshal(rr.Body.Bytes(), &artifacts)
	require.NoError(t, err)
	assert.NotEmpty(t, artifacts)
	assert.Equal(t, 3, artifacts[0].SLSALevel)

	// /api/v1/graph/{digest}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/graph/sha256:52242b9363649daf33fecab71ff1a41988547a97a966b5b127ca91c186d3023b", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	var graph ProvenanceGraph
	err = json.Unmarshal(rr.Body.Bytes(), &graph)
	require.NoError(t, err)
	assert.Len(t, graph.Nodes, 5)
	assert.Len(t, graph.Edges, 4)
	assert.Equal(t, "verified", graph.Nodes[0].Status)
}

func TestAPIDecisionsAndLedgerCheckpoints(t *testing.T) {
	_, mux := setupTestAPIServer()

	// /api/v1/decisions
	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions?namespace=prod", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"total":1`)

	// /api/v1/ledger/checkpoints
	req = httptest.NewRequest(http.MethodGet, "/api/v1/ledger/checkpoints", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"head_index":0`)
	assert.Contains(t, rr.Body.String(), `"integrity_verified":true`)
}

func TestAPIPolicies(t *testing.T) {
	_, mux := setupTestAPIServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "signature_required")
	assert.Contains(t, rr.Body.String(), "provenance_required")
	assert.Contains(t, rr.Body.String(), "vulnerability_gate")
}
