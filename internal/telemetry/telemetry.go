package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	AdmissionLatency     *prometheus.HistogramVec
	DecisionsTotal       *prometheus.CounterVec
	VerificationFailures *prometheus.CounterVec
	CacheHitsTotal       *prometheus.CounterVec
	CacheMissesTotal     *prometheus.CounterVec
	RegistryErrorsTotal  prometheus.Counter
	RiskScorerLatency    prometheus.Histogram
	DegradedModeTotal    *prometheus.CounterVec
	LedgerLength         prometheus.Gauge
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	factory := promauto.With(reg)

	return &Metrics{
		AdmissionLatency: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "aegischain",
				Subsystem: "admission",
				Name:      "latency_seconds",
				Help:      "Admission evaluation latency in seconds",
				Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
			},
			[]string{"verdict", "cache_hit"},
		),
		DecisionsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "aegischain",
				Subsystem: "engine",
				Name:      "decisions_total",
				Help:      "Total count of policy decisions made",
			},
			[]string{"verdict", "namespace", "mode"},
		),
		VerificationFailures: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "aegischain",
				Subsystem: "verify",
				Name:      "failures_total",
				Help:      "Total count of verification failures broken down by reason",
			},
			[]string{"reason"},
		),
		CacheHitsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "aegischain",
				Subsystem: "cache",
				Name:      "hits_total",
				Help:      "Total cache hits for resolved digests and verification results",
			},
			[]string{"type"},
		),
		CacheMissesTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "aegischain",
				Subsystem: "cache",
				Name:      "misses_total",
				Help:      "Total cache misses requiring remote registry/scorer fetch",
			},
			[]string{"type"},
		),
		RegistryErrorsTotal: factory.NewCounter(
			prometheus.CounterOpts{
				Namespace: "aegischain",
				Subsystem: "registry",
				Name:      "errors_total",
				Help:      "Total count of upstream OCI registry errors encountered",
			},
		),
		RiskScorerLatency: factory.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: "aegischain",
				Subsystem: "scorer",
				Name:      "latency_seconds",
				Help:      "Round-trip latency to the dependency risk scorer service",
				Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
			},
		),
		DegradedModeTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "aegischain",
				Subsystem: "engine",
				Name:      "degraded_mode_total",
				Help:      "Total decisions evaluated during degraded dependency or registry mode",
			},
			[]string{"component"},
		),
		LedgerLength: factory.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "aegischain",
				Subsystem: "ledger",
				Name:      "entries_total",
				Help:      "Current total number of entries in the hash-chained decision ledger",
			},
		),
	}
}
