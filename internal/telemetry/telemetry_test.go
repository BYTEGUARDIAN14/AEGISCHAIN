package telemetry

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestMetricsRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	assert.NotNil(t, m.AdmissionLatency)
	assert.NotNil(t, m.DecisionsTotal)
	assert.NotNil(t, m.VerificationFailures)
	assert.NotNil(t, m.CacheHitsTotal)
	assert.NotNil(t, m.CacheMissesTotal)
	assert.NotNil(t, m.RegistryErrorsTotal)
	assert.NotNil(t, m.RiskScorerLatency)
	assert.NotNil(t, m.DegradedModeTotal)
	assert.NotNil(t, m.LedgerLength)

	m.DecisionsTotal.WithLabelValues("allow", "prod", "enforce").Inc()
	m.LedgerLength.Set(42)

	families, err := reg.Gather()
	assert.NoError(t, err)
	assert.NotEmpty(t, families)
}
