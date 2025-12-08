# Backup and Recovery Procedures

This document describes backup strategies, disaster recovery procedures, and data retention for Proxilion MCP Security Gateway.

---

## Data Overview

### What Data Proxilion Stores

| Data Type | Storage | Retention | Criticality |
|-----------|---------|-----------|-------------|
| Session state | Redis | Configurable TTL (default 24h) | Medium |
| Metrics | Prometheus | 15 days default | Low |
| Logs | Container stdout/files | Varies | Medium |
| Configuration | Environment variables | N/A (stateless) | High |
| Alert history | Alertmanager | 120h default | Medium |

### Data NOT Stored

- Tool call content (analyzed, not persisted)
- User credentials (no auth layer)
- MCP server responses

---

## Backup Strategies

### 1. Redis Session State

Session state enables kill chain detection and request rate limiting. Loss means session correlation restarts from zero.

#### Backup Options

**Option A: Redis RDB Snapshots (Recommended)**

```bash
# Enable RDB in redis.conf
save 900 1      # Save if 1 key changed in 15 minutes
save 300 10     # Save if 10 keys changed in 5 minutes
save 60 10000   # Save if 10000 keys changed in 1 minute

dbfilename dump.rdb
dir /var/lib/redis
```

**Backup script:**

```bash
#!/bin/bash
# backup-redis.sh

BACKUP_DIR="/backups/redis"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REDIS_DIR="/var/lib/redis"

# Trigger save
redis-cli BGSAVE

# Wait for save to complete
while [ $(redis-cli LASTSAVE) == $(redis-cli LASTSAVE) ]; do
    sleep 1
done

# Copy dump file
cp "$REDIS_DIR/dump.rdb" "$BACKUP_DIR/dump_$TIMESTAMP.rdb"

# Compress
gzip "$BACKUP_DIR/dump_$TIMESTAMP.rdb"

# Retain last 7 days
find "$BACKUP_DIR" -name "dump_*.rdb.gz" -mtime +7 -delete

echo "Backup completed: dump_$TIMESTAMP.rdb.gz"
```

**Option B: Redis AOF (Append Only File)**

```bash
# Enable AOF in redis.conf
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
```

**Option C: Redis Replication**

```yaml
# docker-compose.yml with replica
services:
  redis-master:
    image: redis:7-alpine
    command: redis-server --appendonly yes

  redis-replica:
    image: redis:7-alpine
    command: redis-server --replicaof redis-master 6379
    depends_on:
      - redis-master
```

### 2. Prometheus Metrics

Metrics provide historical visibility into threat trends.

**Backup script:**

```bash
#!/bin/bash
# backup-prometheus.sh

BACKUP_DIR="/backups/prometheus"
PROMETHEUS_DATA="/prometheus"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create snapshot via API
curl -X POST http://localhost:9090/api/v1/admin/tsdb/snapshot

# Find snapshot directory
SNAPSHOT=$(ls -t "$PROMETHEUS_DATA/snapshots" | head -1)

# Copy snapshot
cp -r "$PROMETHEUS_DATA/snapshots/$SNAPSHOT" "$BACKUP_DIR/prometheus_$TIMESTAMP"

# Compress
tar -czvf "$BACKUP_DIR/prometheus_$TIMESTAMP.tar.gz" -C "$BACKUP_DIR" "prometheus_$TIMESTAMP"
rm -rf "$BACKUP_DIR/prometheus_$TIMESTAMP"

# Retain last 30 days
find "$BACKUP_DIR" -name "prometheus_*.tar.gz" -mtime +30 -delete
```

### 3. Configuration Backup

Configuration is in environment variables and Docker Compose files.

```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/backups/config"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR/$TIMESTAMP"

# Backup Docker Compose files
cp docker-compose.yml "$BACKUP_DIR/$TIMESTAMP/"
cp docker-compose.*.yml "$BACKUP_DIR/$TIMESTAMP/" 2>/dev/null

# Backup environment (excluding secrets)
env | grep -E "^(MODE|SESSION_STORE|ALERT_THRESHOLD|BLOCK_THRESHOLD)" \
    > "$BACKUP_DIR/$TIMESTAMP/env.txt"

# Backup Prometheus config
cp prometheus.yml "$BACKUP_DIR/$TIMESTAMP/"
cp alerts.yml "$BACKUP_DIR/$TIMESTAMP/"

# Backup Grafana dashboards
cp -r grafana/dashboards "$BACKUP_DIR/$TIMESTAMP/" 2>/dev/null

# Compress
tar -czvf "$BACKUP_DIR/config_$TIMESTAMP.tar.gz" -C "$BACKUP_DIR" "$TIMESTAMP"
rm -rf "$BACKUP_DIR/$TIMESTAMP"

echo "Config backup: config_$TIMESTAMP.tar.gz"
```

### 4. Log Backup

```bash
#!/bin/bash
# backup-logs.sh

BACKUP_DIR="/backups/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Export container logs
docker logs proxilion-gateway --since 24h > "$BACKUP_DIR/gateway_$TIMESTAMP.log" 2>&1

# Compress
gzip "$BACKUP_DIR/gateway_$TIMESTAMP.log"

# Retain last 30 days
find "$BACKUP_DIR" -name "gateway_*.log.gz" -mtime +30 -delete
```

---

## Recovery Procedures

### Scenario 1: Gateway Container Crash

**Impact:** Analysis unavailable, requests fail or bypass

**Recovery:**

```bash
# 1. Check container status
docker ps -a | grep proxilion

# 2. View crash logs
docker logs proxilion-gateway --tail 100

# 3. Restart container
docker restart proxilion-gateway

# 4. If persistent issues, recreate
docker-compose down
docker-compose up -d

# 5. Verify health
curl http://localhost:8787/health
```

**RTO:** 1-5 minutes

### Scenario 2: Redis Data Loss

**Impact:** Session correlation lost, kill chain detection resets

**Recovery from RDB:**

```bash
# 1. Stop Redis
docker stop proxilion-redis

# 2. Restore backup
gunzip /backups/redis/dump_LATEST.rdb.gz
cp /backups/redis/dump_LATEST.rdb /var/lib/redis/dump.rdb

# 3. Start Redis
docker start proxilion-redis

# 4. Verify
redis-cli INFO keyspace
```

**Recovery from AOF:**

```bash
# 1. Stop Redis
docker stop proxilion-redis

# 2. Copy AOF file
cp /backups/redis/appendonly.aof /var/lib/redis/

# 3. Start Redis
docker start proxilion-redis
```

**RTO:** 5-15 minutes
**RPO:** Last backup (RDB) or last second (AOF)

### Scenario 3: Complete Host Failure

**Impact:** All services unavailable

**Recovery:**

```bash
# 1. Provision new host

# 2. Install Docker
curl -fsSL https://get.docker.com | sh

# 3. Restore configuration
tar -xzvf /backups/config/config_LATEST.tar.gz
cd config_TIMESTAMP

# 4. Restore Redis data
mkdir -p /var/lib/redis
gunzip -c /backups/redis/dump_LATEST.rdb.gz > /var/lib/redis/dump.rdb

# 5. Start services
docker-compose up -d

# 6. Verify
curl http://localhost:8787/health
```

**RTO:** 30-60 minutes (depending on backup location)

### Scenario 4: Prometheus Data Corruption

**Impact:** Historical metrics lost

**Recovery:**

```bash
# 1. Stop Prometheus
docker stop prometheus

# 2. Clear existing data
rm -rf /prometheus/data/*

# 3. Restore snapshot
tar -xzvf /backups/prometheus/prometheus_LATEST.tar.gz -C /prometheus/snapshots/

# 4. Start Prometheus
docker start prometheus

# 5. Verify
curl http://localhost:9090/api/v1/status/runtimeinfo
```

**RTO:** 15-30 minutes
**RPO:** Last snapshot

---

## Disaster Recovery Plan

### Priority Order

1. **Gateway** - Restore analysis capability first
2. **Redis** - Restore session correlation
3. **Prometheus** - Restore monitoring
4. **Grafana** - Restore dashboards

### Runbook

```
DISASTER RECOVERY RUNBOOK
=========================

1. ASSESS
   [ ] Identify failed components
   [ ] Check backup availability
   [ ] Notify stakeholders

2. PROVISION INFRASTRUCTURE
   [ ] New host or repair existing
   [ ] Docker installed
   [ ] Network connectivity verified

3. RESTORE GATEWAY
   [ ] docker-compose.yml in place
   [ ] Environment variables configured
   [ ] docker-compose up -d gateway
   [ ] curl localhost:8787/health returns OK

4. RESTORE REDIS
   [ ] dump.rdb restored to /var/lib/redis
   [ ] docker-compose up -d redis
   [ ] redis-cli PING returns PONG

5. RESTORE MONITORING
   [ ] Prometheus data restored (optional)
   [ ] docker-compose up -d prometheus grafana
   [ ] Grafana dashboards accessible

6. VERIFY
   [ ] Test /analyze endpoint
   [ ] Check metrics at /metrics
   [ ] Review Grafana dashboards
   [ ] Confirm alerting works

7. POST-INCIDENT
   [ ] Document incident timeline
   [ ] Update backup procedures if needed
   [ ] Schedule post-mortem
```

---

## Backup Schedule Recommendations

| Component | Frequency | Retention | Method |
|-----------|-----------|-----------|--------|
| Redis RDB | Every 6 hours | 7 days | Cron + script |
| Redis AOF | Continuous | N/A | Built-in |
| Prometheus | Daily | 30 days | Snapshot API |
| Config | On change | 90 days | Git or script |
| Logs | Daily | 30 days | Log rotation |

### Cron Configuration

```cron
# /etc/cron.d/proxilion-backup

# Redis backup every 6 hours
0 */6 * * * root /opt/proxilion/scripts/backup-redis.sh

# Prometheus backup daily at 2 AM
0 2 * * * root /opt/proxilion/scripts/backup-prometheus.sh

# Config backup on Sundays at 3 AM
0 3 * * 0 root /opt/proxilion/scripts/backup-config.sh

# Log backup daily at 1 AM
0 1 * * * root /opt/proxilion/scripts/backup-logs.sh
```

---

## High Availability Considerations

### For Production Deployments

1. **Multiple Gateway Instances**
   ```yaml
   services:
     gateway:
       deploy:
         replicas: 3
   ```

2. **Redis Sentinel for HA**
   ```yaml
   services:
     redis-sentinel:
       image: redis:7-alpine
       command: redis-sentinel /etc/redis/sentinel.conf
   ```

3. **Load Balancer**
   - Use NGINX, HAProxy, or cloud LB in front of gateway instances
   - Health check: `GET /health`

4. **Cross-Region Replication**
   - Redis replication to standby region
   - Prometheus remote write to secondary

---

## Data Retention Policies

### Compliance Considerations

| Regulation | Requirement | Proxilion Impact |
|------------|-------------|------------------|
| GDPR | Data minimization | Session data auto-expires |
| SOC 2 | Audit logging | Enable log retention |
| PCI DSS | Log retention 1 year | Increase log retention |

### Configuring Retention

**Session TTL:**
```bash
# Environment variable
SESSION_TTL_HOURS=24  # Default
SESSION_TTL_HOURS=168 # 1 week
```

**Prometheus Retention:**
```yaml
# prometheus.yml command line
prometheus:
  command:
    - '--storage.tsdb.retention.time=90d'
```

**Log Retention:**
```yaml
# docker-compose.yml
services:
  gateway:
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "10"
```

---

## Testing Backups

### Monthly Backup Verification

```bash
#!/bin/bash
# test-backup-restore.sh

echo "=== Backup Verification Test ==="

# 1. Create test environment
docker-compose -f docker-compose.test.yml up -d

# 2. Restore Redis backup
gunzip -c /backups/redis/dump_LATEST.rdb.gz > /tmp/test-dump.rdb
docker cp /tmp/test-dump.rdb test-redis:/data/dump.rdb
docker restart test-redis

# 3. Verify data
KEYS=$(docker exec test-redis redis-cli DBSIZE)
echo "Redis keys restored: $KEYS"

# 4. Test gateway
docker exec test-gateway curl -s localhost:8787/health
echo "Gateway health: $?"

# 5. Cleanup
docker-compose -f docker-compose.test.yml down -v

echo "=== Verification Complete ==="
```

---

## Emergency Contacts

Update this section with your organization's contacts:

| Role | Name | Contact |
|------|------|---------|
| Primary On-Call | TBD | TBD |
| Secondary On-Call | TBD | TBD |
| Infrastructure Lead | TBD | TBD |
| Security Lead | TBD | TBD |
