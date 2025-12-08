# Troubleshooting Guide

This guide helps diagnose and resolve common issues with Proxilion MCP Security Gateway.

---

## Quick Diagnostics

Run these commands first to assess system health:

```bash
# Check gateway is running
curl http://localhost:8787/health

# Check metrics endpoint
curl http://localhost:8787/metrics | head -20

# Check Docker container status
docker ps | grep proxilion

# Check container logs
docker logs proxilion-gateway --tail 50

# Check Redis connection (if using Redis)
redis-cli ping
```

---

## Deployment Issues

### Gateway Fails to Start

**Symptoms:**
- Container exits immediately
- "Address already in use" error
- "Cannot connect to Redis" error

**Diagnosis:**

```bash
# Check container logs
docker logs proxilion-gateway 2>&1 | tail -50

# Check if port is in use
lsof -i :8787
netstat -tlnp | grep 8787

# Check Redis is running
docker ps | grep redis
redis-cli ping
```

**Solutions:**

1. **Port conflict:**
   ```bash
   # Kill process using the port
   kill $(lsof -t -i:8787)

   # Or use different port
   docker run -p 8788:8787 ...
   ```

2. **Redis not available:**
   ```bash
   # Start Redis first
   docker run -d --name redis -p 6379:6379 redis:7-alpine

   # Or use in-memory store for testing
   docker run -e SESSION_STORE=inmemory ...
   ```

3. **Missing environment variables:**
   ```bash
   # Required variables
   docker run \
     -e MODE=monitor \
     -e SESSION_STORE=inmemory \
     proxilion/gateway
   ```

### Container Keeps Restarting

**Symptoms:**
- Container restarts repeatedly
- "unhealthy" status in docker ps

**Diagnosis:**

```bash
# Check restart count
docker inspect proxilion-gateway --format='{{.RestartCount}}'

# Check health check failures
docker inspect proxilion-gateway --format='{{json .State.Health}}'

# Check OOM kills
docker inspect proxilion-gateway --format='{{.State.OOMKilled}}'
```

**Solutions:**

1. **Health check timeout:**
   ```yaml
   # Increase health check timeout in docker-compose.yml
   healthcheck:
     test: ["CMD", "curl", "-f", "http://localhost:8787/health"]
     interval: 30s
     timeout: 10s  # Increase from 5s
     retries: 5    # Increase from 3
   ```

2. **Insufficient memory:**
   ```yaml
   # Add memory limits
   deploy:
     resources:
       limits:
         memory: 512M
       reservations:
         memory: 256M
   ```

3. **Redis connection flapping:**
   ```bash
   # Check Redis max connections
   redis-cli CONFIG GET maxclients

   # Increase if needed
   redis-cli CONFIG SET maxclients 10000
   ```

### Network Connectivity Problems

**Symptoms:**
- "Connection refused" errors
- Requests time out
- Cannot reach gateway from other containers

**Diagnosis:**

```bash
# Check container networks
docker network ls
docker network inspect proxilion-network

# Check container IP
docker inspect proxilion-gateway --format='{{.NetworkSettings.IPAddress}}'

# Test connectivity from another container
docker run --rm --network proxilion-network alpine ping gateway
```

**Solutions:**

1. **Containers on different networks:**
   ```bash
   # Connect to same network
   docker network connect proxilion-network your-client-container
   ```

2. **Firewall blocking:**
   ```bash
   # Check iptables (Linux)
   sudo iptables -L -n | grep 8787

   # macOS - check pf
   sudo pfctl -s rules | grep 8787
   ```

3. **Docker DNS not resolving:**
   ```bash
   # Use IP instead of hostname
   curl http://172.17.0.2:8787/health

   # Or add custom DNS
   docker run --dns 8.8.8.8 ...
   ```

---

## Runtime Issues

### High Latency

**Symptoms:**
- P95 latency > 100ms
- Requests timing out
- Slow response from /analyze endpoint

**Diagnosis:**

```bash
# Check latency metrics
curl -s http://localhost:8787/metrics | grep duration

# Time a request
time curl -X POST http://localhost:8787/analyze \
  -H "Content-Type: application/json" \
  -d '{"tool_call":{"Bash":{"command":"ls"}},"user_id":"test","session_id":"test"}'

# Check Redis latency
redis-cli --latency

# Check system resources
docker stats proxilion-gateway
```

**Solutions:**

1. **Redis latency:**
   ```bash
   # Check Redis slow log
   redis-cli SLOWLOG GET 10

   # Enable Redis pipelining in config
   # Or switch to in-memory store for testing
   ```

2. **Semantic analysis enabled:**
   ```bash
   # Check if semantic analysis is adding latency
   curl -s http://localhost:8787/metrics | grep semantic

   # Disable semantic analysis
   docker run -e ENABLE_SEMANTIC_ANALYSIS=false ...
   ```

3. **Too many analyzers running:**
   - Review analyzer configuration
   - Profile individual analyzer latency
   - Consider disabling non-critical analyzers

4. **Insufficient CPU:**
   ```yaml
   deploy:
     resources:
       limits:
         cpus: '2'
       reservations:
         cpus: '1'
   ```

### Memory Usage Spikes

**Symptoms:**
- Container OOM killed
- Memory grows over time
- Slow garbage collection

**Diagnosis:**

```bash
# Check memory usage
docker stats proxilion-gateway --no-stream

# Check for memory leaks (Rust shouldn't have these, but check session storage)
redis-cli INFO memory

# Check session count
redis-cli DBSIZE
```

**Solutions:**

1. **Session accumulation:**
   ```bash
   # Set session TTL
   docker run -e SESSION_TTL_HOURS=24 ...

   # Manually clean old sessions
   redis-cli KEYS "session:*" | head -100
   ```

2. **Large request bodies:**
   - Add request size limits at API gateway
   - Truncate large tool call arguments before analysis

3. **Increase container memory:**
   ```yaml
   deploy:
     resources:
       limits:
         memory: 1G
   ```

### Redis Connection Failures

**Symptoms:**
- "Redis connection error" in logs
- Intermittent 500 errors
- Session tracking not working

**Diagnosis:**

```bash
# Check Redis is accepting connections
redis-cli ping

# Check connection count
redis-cli CLIENT LIST | wc -l

# Check Redis memory
redis-cli INFO memory | grep used_memory_human

# Check Proxilion Redis status
curl -s http://localhost:8787/metrics | grep redis
```

**Solutions:**

1. **Connection pool exhausted:**
   ```bash
   # Increase Redis max clients
   redis-cli CONFIG SET maxclients 10000
   ```

2. **Redis memory full:**
   ```bash
   # Check memory
   redis-cli INFO memory

   # Set eviction policy
   redis-cli CONFIG SET maxmemory-policy volatile-lru
   ```

3. **Network timeout:**
   ```bash
   # Check Redis timeout setting
   redis-cli CONFIG GET timeout

   # Increase timeout
   redis-cli CONFIG SET timeout 300
   ```

4. **Authentication failure:**
   ```bash
   # Verify password
   redis-cli -a YOUR_PASSWORD ping

   # Update REDIS_URL with password
   docker run -e REDIS_URL=redis://:password@localhost:6379 ...
   ```

---

## Detection Issues

### False Positives (Legitimate Commands Blocked)

**Symptoms:**
- Normal commands getting blocked
- DevOps/security work triggering alerts
- High alert volume for safe operations

**Diagnosis:**

```bash
# Check what's being blocked
docker logs proxilion-gateway 2>&1 | grep "Block\|Terminate"

# Get detailed threat analysis
curl -X POST http://localhost:8787/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "tool_call": {"Bash": {"command": "YOUR_COMMAND_HERE", "args": [], "env": {}}},
    "user_id": "test",
    "session_id": "test"
  }' | jq .
```

**Solutions:**

1. **Switch to monitor mode temporarily:**
   ```bash
   docker run -e MODE=monitor ...
   ```

2. **Adjust thresholds:**
   ```bash
   # Raise block threshold from 70 to 80
   docker run -e BLOCK_THRESHOLD=80 ...
   ```

3. **Review triggering patterns:**
   - Check which analyzer triggered
   - Review the specific pattern matched
   - Consider if pattern is too broad

4. **Document allowlist requests:**
   - Create ticket for security team
   - Include command, user, business justification

### Missing Detections (Threats Not Caught)

**Symptoms:**
- Known attack patterns not detected
- Low threat scores for malicious commands
- Session correlation not working

**Diagnosis:**

```bash
# Test known attack pattern
curl -X POST http://localhost:8787/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "tool_call": {"Bash": {"command": "nmap -sV target.com", "args": [], "env": {}}},
    "user_id": "test",
    "session_id": "test"
  }' | jq .

# Check analyzer is active
docker logs proxilion-gateway 2>&1 | grep "analyzer"
```

**Solutions:**

1. **Verify analyzers are running:**
   - Check logs for analyzer initialization
   - Verify no analyzer errors in metrics

2. **Check session_id is consistent:**
   ```bash
   # Session tracking requires consistent session_id
   # Bad: random session_id per request
   # Good: stable session_id per user session
   ```

3. **Enable additional analyzers:**
   - AI Autonomy, Multi-Target, etc. require configuration
   - Check which analyzers are active

4. **Report missing pattern:**
   - Open issue with command and expected detection
   - Provide context for pattern addition

### Session Correlation Not Working

**Symptoms:**
- Kill chain detection not triggering
- Request rate analyzer not detecting bursts
- Multi-phase attacks not correlated

**Diagnosis:**

```bash
# Check session is being tracked
redis-cli HGETALL "session:YOUR_SESSION_ID"

# Check request timestamps
redis-cli LRANGE "session:YOUR_SESSION_ID:requests" 0 -1

# Verify session_id in requests
# All requests in a session MUST use the same session_id
```

**Solutions:**

1. **Ensure consistent session_id:**
   ```javascript
   // Generate once per session, reuse for all requests
   const sessionId = `session-${userId}-${Date.now()}`;
   ```

2. **Check Redis TTL:**
   ```bash
   # Sessions may have expired
   redis-cli TTL "session:YOUR_SESSION_ID"
   ```

3. **Verify Redis connectivity:**
   ```bash
   curl -s http://localhost:8787/metrics | grep redis_connected
   ```

---

## Integration Issues

### Client Library Connection Problems

**Symptoms:**
- Client cannot connect to gateway
- Timeout errors
- SSL/TLS errors

**Diagnosis:**

```bash
# Test basic connectivity
curl http://localhost:8787/health

# Test from client's perspective
# (run inside client container or on client machine)
curl http://gateway:8787/health
```

**Solutions:**

1. **Wrong endpoint URL:**
   ```javascript
   // Ensure URL matches gateway location
   const client = new ProxilionMCPClient({
     proxilionEndpoint: 'http://localhost:8787',  // Check this
   });
   ```

2. **CORS issues (browser-based clients):**
   - Gateway has CORS enabled by default
   - Check browser console for CORS errors
   - Verify Origin header is allowed

3. **Network isolation:**
   ```bash
   # Ensure client can reach gateway
   docker network connect proxilion-network client-container
   ```

### MCP Protocol Errors

**Symptoms:**
- "Invalid JSON" errors
- "Unknown tool type" errors
- Request parsing failures

**Diagnosis:**

```bash
# Check request format
curl -X POST http://localhost:8787/analyze \
  -H "Content-Type: application/json" \
  -d '{"tool_call": {"Bash": {"command": "ls"}}, "user_id": "test", "session_id": "test"}'

# Check response
curl -X POST http://localhost:8787/analyze \
  -H "Content-Type: application/json" \
  -d '...' | jq .
```

**Solutions:**

1. **Correct request format:**
   ```json
   {
     "tool_call": {
       "Bash": {
         "command": "the command",
         "args": [],
         "env": {}
       }
     },
     "user_id": "user@example.com",
     "session_id": "session-123"
   }
   ```

2. **Supported tool types:**
   - `Bash` - Shell commands
   - `FileSystem` - File operations
   - `Network` - Network requests
   - `Database` - Database queries

3. **Content-Type header:**
   ```bash
   # Must include Content-Type
   curl -H "Content-Type: application/json" ...
   ```

---

## Performance Tuning

### Optimize for High Throughput

```yaml
# docker-compose.yml
services:
  gateway:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 2G
        reservations:
          cpus: '2'
          memory: 1G
    environment:
      - RUST_LOG=warn  # Reduce logging
      - ENABLE_SEMANTIC_ANALYSIS=false  # Disable slow analysis
```

### Optimize for Low Latency

```bash
# Use in-memory session store
docker run -e SESSION_STORE=inmemory ...

# Disable semantic analysis
docker run -e ENABLE_SEMANTIC_ANALYSIS=false ...

# Run on dedicated hardware
# Avoid noisy neighbors in shared environments
```

### Optimize for Cost

```bash
# Disable semantic analysis (Claude API costs)
docker run -e ENABLE_SEMANTIC_ANALYSIS=false ...

# Use smaller Redis instance
# In-memory store for non-critical deployments
```

---

## Log Interpretation

### Log Levels

| Level | Meaning |
|-------|---------|
| ERROR | System failure, requires attention |
| WARN | Potential issue, monitor |
| INFO | Normal operation, key events |
| DEBUG | Detailed debugging (verbose) |

### Common Log Messages

**Normal Operation:**
```
INFO  gateway: Listening on 0.0.0.0:8787
INFO  gateway: Redis connected
INFO  gateway: Analysis complete decision=Allow score=15
```

**Warnings:**
```
WARN  gateway: Redis connection retry attempt=2
WARN  gateway: High threat score detected score=75 user=user@example.com
WARN  gateway: Session terminated session_id=xxx
```

**Errors:**
```
ERROR gateway: Redis connection failed error="Connection refused"
ERROR gateway: Analysis failed error="Timeout"
ERROR gateway: Invalid request format
```

### Enable Debug Logging

```bash
docker run -e RUST_LOG=debug proxilion/gateway
```

**Warning:** Debug logging is verbose and impacts performance. Use only for troubleshooting.

---

## Debug Mode

### Enable Full Request Logging

```bash
docker run -e LOG_ALL_REQUESTS=true -e RUST_LOG=debug proxilion/gateway
```

### Inspect Individual Request

```bash
# Send request with detailed output
curl -v -X POST http://localhost:8787/analyze \
  -H "Content-Type: application/json" \
  -d '{"tool_call":{"Bash":{"command":"ls"}},"user_id":"test","session_id":"test"}' 2>&1
```

### Profile Analyzer Performance

```bash
# Check per-analyzer metrics
curl -s http://localhost:8787/metrics | grep "analyzer"
```

---

## Getting Help

### Before Opening an Issue

1. Check this troubleshooting guide
2. Search existing GitHub issues
3. Collect diagnostic information:
   - Gateway version
   - Docker/OS version
   - Relevant logs
   - Steps to reproduce

### Diagnostic Information to Collect

```bash
# Version info
docker inspect proxilion-gateway --format='{{.Config.Image}}'

# System info
uname -a
docker version

# Logs (last 100 lines)
docker logs proxilion-gateway --tail 100 2>&1 > proxilion-logs.txt

# Metrics snapshot
curl http://localhost:8787/metrics > proxilion-metrics.txt

# Health check
curl http://localhost:8787/health > proxilion-health.txt
```

### Contact

- GitHub Issues: https://github.com/clay-good/proxilion/issues
- Include: logs, metrics, reproduction steps
