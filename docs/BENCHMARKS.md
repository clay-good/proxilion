# Performance Benchmarks

This document explains how to run and interpret performance benchmarks for Proxilion MCP Security Gateway.

---

## Running Benchmarks

### Prerequisites

```bash
# Ensure you have Rust installed
rustc --version

# Benchmarks require criterion.rs (included as dev dependency)
```

### Run All Benchmarks

```bash
# Full benchmark suite (takes 5-10 minutes)
cargo bench -p threat-engine

# Results saved to: target/criterion/
```

### Run Specific Benchmarks

```bash
# Run only safe request benchmark
cargo bench -p threat-engine -- analyze_safe

# Run only throughput benchmarks
cargo bench -p threat-engine -- throughput

# Run only tool type benchmarks
cargo bench -p threat-engine -- tool_types
```

### Quick Benchmark (Less Iterations)

```bash
# Faster but less precise
cargo bench -p threat-engine -- --quick
```

---

## Benchmark Categories

### 1. Single Request Analysis

| Benchmark | Description | Expected Result |
|-----------|-------------|-----------------|
| `analyze_safe_request` | Benign `ls` command | <1ms |
| `analyze_suspicious_request` | `nmap` scan | <5ms |
| `analyze_high_threat_request` | Credential + exfil combo | <10ms |
| `analyze_complex_request` | Multi-pattern command | <15ms |

### 2. Session-Aware Analysis

| Benchmark | Description | Expected Result |
|-----------|-------------|-----------------|
| `analyze_session_aware_empty` | No session history | <5ms |
| `analyze_session_aware_active` | 1000 requests in history | <10ms |

### 3. Throughput

| Benchmark | Description | Target |
|-----------|-------------|--------|
| `throughput/10` | 10 requests batch | >1000/sec |
| `throughput/100` | 100 requests batch | >5000/sec |
| `throughput/1000` | 1000 requests batch | >10000/sec |

### 4. Command Length Impact

| Benchmark | Description | Expected Result |
|-----------|-------------|-----------------|
| `command_length/100` | 100 char command | <1ms |
| `command_length/1000` | 1KB command | <2ms |
| `command_length/10000` | 10KB command | <10ms |

### 5. Tool Type Comparison

| Benchmark | Description |
|-----------|-------------|
| `tool_types/bash` | Shell command |
| `tool_types/filesystem_read` | File read |
| `tool_types/filesystem_write` | File write |
| `tool_types/network` | HTTP request |
| `tool_types/database` | SQL query |

---

## Interpreting Results

### Criterion Output

```
analyze_safe_request    time:   [145.23 us 146.89 us 148.67 us]
                        change: [-1.2% +0.5% +2.1%] (p = 0.58 > 0.05)
                        No change in performance detected.
```

- **time**: [lower_bound median upper_bound] - 95% confidence interval
- **change**: Comparison to previous run (if available)
- **p-value**: Statistical significance of change

### Performance Targets

| Metric | Target | Acceptable | Needs Attention |
|--------|--------|------------|-----------------|
| P50 latency | <5ms | <25ms | >50ms |
| P95 latency | <25ms | <50ms | >100ms |
| P99 latency | <50ms | <100ms | >200ms |
| Throughput | >10k/sec | >5k/sec | <1k/sec |

### HTML Reports

After running benchmarks, view detailed HTML reports:

```bash
# Open in browser
open target/criterion/report/index.html
```

Reports include:
- Latency distribution graphs
- Throughput over time
- Comparison with previous runs
- Statistical analysis

---

## Continuous Benchmarking

### CI Integration

Add to your CI pipeline:

```yaml
# .github/workflows/benchmark.yml
name: Benchmarks
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Run benchmarks
        run: cargo bench -p threat-engine -- --noplot

      - name: Archive results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: target/criterion/
```

### Tracking Performance Over Time

```bash
# Save baseline
cargo bench -p threat-engine -- --save-baseline main

# Compare against baseline
cargo bench -p threat-engine -- --baseline main
```

---

## Performance Tuning

### If Latency is Too High

1. **Check regex patterns**: Complex regexes slow analysis
2. **Reduce active analyzers**: Disable non-critical analyzers
3. **Increase hardware**: CPU-bound workload
4. **Profile with flamegraph**:
   ```bash
   cargo install flamegraph
   cargo flamegraph -p threat-engine --bench threat_analysis
   ```

### If Throughput is Too Low

1. **Check connection pooling**: Redis/network bottleneck
2. **Increase parallelism**: More async workers
3. **Batch requests**: Analyze multiple requests together
4. **Check memory allocation**: High allocation rate

---

## Benchmark Limitations

1. **Synthetic workload**: Real traffic patterns may differ
2. **Single-threaded**: Benchmarks run single-threaded by default
3. **No network I/O**: Excludes Redis/HTTP latency
4. **Cold vs warm**: First run may be slower (JIT, caches)

### Production vs Benchmark Differences

| Factor | Benchmark | Production |
|--------|-----------|------------|
| Redis latency | Not included | +1-5ms |
| Network I/O | Not included | +1-10ms |
| Concurrent requests | Sequential | Parallel |
| Session store | In-memory | Redis |

**Expected production latency = benchmark + 5-20ms**

---

## Adding New Benchmarks

To add a benchmark for a new analyzer or feature:

```rust
// In benches/threat_analysis.rs

fn bench_new_analyzer(c: &mut Criterion) {
    let tool_call = create_test_tool_call();

    c.bench_function("new_analyzer", |b| {
        b.iter(|| analyze_tool_call(black_box(&tool_call)))
    });
}

// Add to criterion_group!
criterion_group!(
    benches,
    // ... existing benchmarks
    bench_new_analyzer,
);
```

---

## Historical Results

Track benchmark results over releases:

| Version | P50 (ms) | P95 (ms) | Throughput (req/s) |
|---------|----------|----------|-------------------|
| 0.1.0 | TBD | TBD | TBD |

Run benchmarks and record results after each release.
