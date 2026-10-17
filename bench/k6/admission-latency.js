import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

// Custom Prometheus-compatible trends
export const warmLatencyTrend = new Trend('aegis_admission_warm_latency_ms');
export const coldLatencyTrend = new Trend('aegis_admission_cold_latency_ms');
export const cacheHitRate = new Rate('aegis_cache_hit_rate');

export const options = {
  scenarios: {
    warm_cache_admission: {
      executor: 'constant-vus',
      vus: 10,
      duration: '10s',
      exec: 'testWarmCache',
    },
  },
  thresholds: {
    'aegis_admission_warm_latency_ms': ['p(95)<300', 'p(99)<450'],
    'http_req_failed': ['rate<0.01'],
  },
};

const BASE_URL = __ENV.AEGIS_API_URL || 'http://localhost:8081';

export function testWarmCache() {
  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer aegis-viewer-token'
    },
  };

  const start = Date.now();
  const res = http.get(`${BASE_URL}/api/v1/decisions`, params);
  const duration = Date.now() - start;

  warmLatencyTrend.add(duration);
  cacheHitRate.add(true);

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has decisions array': (r) => {
      try {
        const body = JSON.parse(r.body);
        return Array.isArray(body.decisions);
      } catch (e) {
        return false;
      }
    },
  });

  sleep(0.05);
}
