# Load Testing Suite

This directory contains load testing infrastructure for validating Proxilion MCP Gateway performance and scalability claims.

---

## Quick Start

```bash
# Install k6 (load testing tool)
# macOS
brew install k6

# Linux
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6

# Docker
docker pull grafana/k6

# Run baseline test
k6 run loadtest/baseline.js

# Run stress test
k6 run loadtest/stress.js

# Run soak test (long duration)
k6 run loadtest/soak.js
```

---

## Test Scenarios

### 1. Baseline Test (`baseline.js`)
- **Purpose:** Establish performance baseline
- **Duration:** 5 minutes
- **VUs:** 10 concurrent users
- **Expected:** P95 < 50ms, 0% errors

### 2. Stress Test (`stress.js`)
- **Purpose:** Find breaking point
- **Duration:** 15 minutes
- **VUs:** Ramp from 10 to 500
- **Expected:** Identify max throughput

### 3. Spike Test (`spike.js`)
- **Purpose:** Test sudden traffic bursts
- **Duration:** 10 minutes
- **VUs:** Burst from 10 to 200 and back
- **Expected:** Recovery within 30 seconds

### 4. Soak Test (`soak.js`)
- **Purpose:** Test long-term stability
- **Duration:** 1 hour
- **VUs:** 50 constant
- **Expected:** No memory leaks, stable latency

---

## Running Tests

### Prerequisites

1. Gateway must be running:
   ```bash
   docker-compose up -d gateway
   ```

2. Verify health:
   ```bash
   curl http://localhost:8787/health
   ```

### Command Options

```bash
# Standard run with console output
k6 run loadtest/baseline.js

# Output to JSON
k6 run --out json=results.json loadtest/baseline.js

# Output to InfluxDB (for Grafana visualization)
k6 run --out influxdb=http://localhost:8086/k6 loadtest/baseline.js

# Override VUs and duration
k6 run -u 100 -d 10m loadtest/baseline.js

# Run with environment variables
k6 run -e TARGET_URL=http://gateway:8787 loadtest/baseline.js
```

### Docker Run

```bash
# Run k6 in Docker (useful for CI)
docker run --rm -i --network=proxilion-network grafana/k6 run - < loadtest/baseline.js
```

---

## Performance Targets

| Metric | Target | Acceptable | Needs Attention |
|--------|--------|------------|-----------------|
| P50 Latency | < 5ms | < 25ms | > 50ms |
| P95 Latency | < 25ms | < 50ms | > 100ms |
| P99 Latency | < 50ms | < 100ms | > 200ms |
| Throughput | > 10,000/sec | > 5,000/sec | < 1,000/sec |
| Error Rate | 0% | < 0.1% | > 1% |

---

## Interpreting Results

### k6 Output

```
     data_received..................: 1.2 GB  2.0 MB/s
     data_sent......................: 89 MB   148 kB/s
     http_req_blocked...............: avg=2.13µs  min=1µs    p(95)=4µs    max=1.2ms
     http_req_connecting............: avg=0s      min=0s     p(95)=0s     max=0s
     http_req_duration..............: avg=4.2ms   min=1.1ms  p(95)=15ms   max=156ms
       { expected_response:true }...: avg=4.2ms   min=1.1ms  p(95)=15ms   max=156ms
     http_req_failed................: 0.00%   ✓ 0        ✗ 612345
     http_req_rate..................: 10205/s
     http_reqs......................: 612345  10205/s
     iteration_duration.............: avg=4.9ms   min=1.5ms  p(95)=17ms   max=158ms
     iterations.....................: 612345  10205/s
     vus............................: 50      min=50     max=50
     vus_max........................: 50      min=50     max=50
```

### Key Metrics

- **http_req_duration:** Total request time (what matters most)
- **http_req_failed:** Error rate (should be 0%)
- **http_reqs:** Total requests per second (throughput)
- **p(95):** 95th percentile latency

---

## CI Integration

### GitHub Actions

```yaml
# .github/workflows/loadtest.yml
name: Load Test

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  loadtest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start Gateway
        run: docker-compose up -d

      - name: Wait for healthy
        run: |
          for i in {1..30}; do
            curl -s http://localhost:8787/health && break
            sleep 2
          done

      - name: Run load test
        uses: grafana/k6-action@v0.3.1
        with:
          filename: loadtest/baseline.js
          flags: --out json=results.json

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: loadtest-results
          path: results.json

      - name: Check thresholds
        run: |
          # Fail if P95 > 50ms
          P95=$(jq '.metrics.http_req_duration.values["p(95)"]' results.json)
          if (( $(echo "$P95 > 50" | bc -l) )); then
            echo "P95 latency $P95 ms exceeds threshold"
            exit 1
          fi
```

---

## Troubleshooting

### High Latency

1. Check Redis connection:
   ```bash
   redis-cli --latency
   ```

2. Check CPU usage:
   ```bash
   docker stats proxilion-gateway
   ```

3. Profile with flamegraph:
   ```bash
   cargo flamegraph -p threat-engine --bench threat_analysis
   ```

### Connection Errors

1. Check gateway health:
   ```bash
   curl http://localhost:8787/health
   ```

2. Check container logs:
   ```bash
   docker logs proxilion-gateway --tail 100
   ```

3. Verify network:
   ```bash
   docker network inspect proxilion-network
   ```

### Memory Growth

1. Monitor container memory:
   ```bash
   docker stats --no-stream proxilion-gateway
   ```

2. Check Redis memory:
   ```bash
   redis-cli INFO memory
   ```
