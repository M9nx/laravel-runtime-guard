# RuntimeGuard Features & Optimizations v2.0

## 🛡️ Security Guards

### Core Guards
| Guard | Detects |
|-------|---------|
| **SQL Injection** | UNION attacks, boolean-based, time-based, stacked queries, encoding bypasses |
| **XSS** | Script tags, event handlers, JavaScript URIs, DOM-based XSS, encoded payloads |
| **Command Injection** | Shell metacharacters, command chaining, dangerous commands, path traversal |
| **File Operations** | Path traversal, null bytes, protocol wrappers, dangerous extensions |

### New Guards (v2.0)
| Guard | Detects |
|-------|---------|
| **SSRF** | Internal IPs, cloud metadata endpoints (AWS/GCP/Azure), DNS rebinding |
| **Mass Assignment** | Dangerous fields (is_admin, role, password), forbidden attributes |
| **Deserialization** | PHP object injection, PHAR wrappers, gadget chain signatures |
| **NoSQL Injection** | MongoDB operators ($where, $gt, $regex), JSON-encoded operators |
| **GraphQL** | Query depth limits, complexity analysis, introspection blocking |
| **Anomaly Detection** | Behavioral baselines, z-score analysis, Welford's algorithm |

---

## ⚡ Performance Optimizations

### 1. Deduplication Cache
- LRU cache for recently inspected inputs
- Skips re-inspection of identical payloads
- Configurable size and TTL

### 2. Request Sampling
- Inspect only a percentage of requests (e.g., 10%)
- Always sample suspicious-looking inputs
- Per-route sampling configuration

### 3. Input Limiting
- Max input size: 64KB default
- Max array depth: 10 levels
- Max array items: 1000 elements
- Prevents DoS via large payloads

### 4. Tiered Inspection
- **Quick Scan**: Fast, high-confidence pattern checks
- **Deep Inspection**: Thorough analysis only if needed
- Short-circuits on first threat detection

### 5. Pattern Pre-compilation
- Regex patterns compiled once at boot
- Cached across guard instances
- Combined patterns for single-pass matching

### 6. Bloom Filter (v2.0)
- O(1) probabilistic pattern pre-screening
- Configurable false positive rate (default: 0.01)
- Dramatically reduces full regex evaluations

### 7. JIT Pattern Warming (v2.0)
- PCRE JIT detection and optimization
- Pattern warming on boot for hot paths
- Persistent cache for warmed patterns

### 8. Lazy Guard Resolution (v2.0)
- Deferred guard instantiation via proxy
- Guards loaded only when first needed
- Reduces memory footprint for unused guards

### 9. Streaming Inspector (v2.0)
- Chunk-based inspection for large inputs
- Configurable chunk size and overlap
- Memory-efficient processing of files/payloads

### 10. Shared Memory Store (v2.0)
- Swoole table support for high-performance
- APCu fallback for traditional deployments
- Inter-worker state sharing for Octane

---

## 🔄 Execution Strategies

| Strategy | Behavior |
|----------|----------|
| `full` | Run all guards, collect all results |
| `short_circuit` | Stop on first threat detected |
| `threshold` | Stop when threat level threshold reached |

---

## 📊 Advanced Features

### Threat Correlation
- Track events by IP, user ID, session
- Configurable time window (default: 5 min)
- Alert when threshold exceeded

### Progressive Enforcement
- **Level 1**: Log only
- **Level 2**: Alert (after 3 events)
- **Level 3**: Block (after 5 events)
- Auto-escalation based on repeated violations

### Route Profiles
- Different guard configs per route pattern
- API routes: lighter inspection
- Admin routes: full protection

### Feature Flags
- Toggle guards at runtime
- No deployment needed
- Cache-backed for performance

---

## 🔧 Developer Experience (v2.0)

### Guard Generator
```bash
# Create a new guard
php artisan make:guard CustomGuard

# Create anomaly detection guard
php artisan make:guard AnomalyGuard --anomaly

# Create API-focused guard
php artisan make:guard ApiGuard --api
```

### Telescope Integration
- Records all security events
- Correlates with request logs
- Links to threat intelligence

### Laravel Pulse Integration
- Real-time security metrics dashboard
- Guards execution timing
- Threat detection counters

### OpenAPI Validator
- Validate requests against OpenAPI specs
- Parameter type and format checking
- Required field validation

### Health Check Endpoint
```
GET /runtime-guard/health
GET /runtime-guard/health/detailed
```

### Debug Mode
- Detailed inspection logging
- Pattern match explanations
- Performance timing breakdown

---

## 📈 Analytics & Threat Intelligence (v2.0)

### Attack Fingerprinting
- Unique attack signature generation
- Pattern similarity scoring
- Campaign tracking

### STIX 2.1 Export
- Standard threat intelligence format
- MITRE ATT&CK mapping
- IOC export for sharing

### Geo-IP Correlation
- MaxMind/IP-API support
- Geographic clustering detection
- VPN/Tor identification

### Trend Analysis
- Hourly/daily/weekly trends
- Anomaly detection in patterns
- Forecasting with linear regression

### Compliance Reporting
- PCI-DSS compliance checks
- OWASP Top 10 coverage
- SOC 2 Type II evidence

---

## 🚧 Constraints

| Constraint | Limit | Reason |
|------------|-------|--------|
| Max input size | 64KB | Prevent memory exhaustion |
| Max array depth | 10 | Prevent stack overflow |
| Max array items | 1000 | Prevent CPU exhaustion |
| Dedup cache size | 1000 entries | Memory bounds |
| Dedup TTL | 60 seconds | Freshness vs memory |
| Correlation window | 5 minutes | Balance detection vs memory |
| Guard timeout | 100ms | Prevent slow guards blocking |
| Pipeline timeout | 500ms | Total inspection budget |
| Bloom filter size | 10,000 | Memory vs accuracy |
| GraphQL max depth | 10 | Prevent DoS |
| GraphQL max complexity | 100 | Prevent DoS |

---

## 📝 Response Modes

| Mode | Behavior |
|------|----------|
| `block` | Throw exception, halt request |
| `log` | Log threat, continue execution |
| `silent` | Record internally only |
| `dry_run` | Full inspection, no action |

---

## 🧪 Testing Support

- `RuntimeGuard::fake()` for test isolation
- Assertion helpers: `assertThreatDetected()`, `assertGuardTriggered()`
- Simulate threats without real inspection

---

## 📢 Events Dispatched

- `ThreatDetected` - When any guard detects a threat
- `InspectionCompleted` - After each inspection cycle
- `CorrelationThresholdExceeded` - When correlation limit hit

---

## 🔧 Artisan Commands

```bash
runtime-guard:list      # Show all guards
runtime-guard:test      # Test a guard with input
runtime-guard:status    # System health check
runtime-guard:toggle    # Enable/disable guards
make:guard              # Generate new guard (v2.0)
```

---

## 📦 New Classes (v2.0)

### Guards
- `SsrfGuard` - Server-Side Request Forgery detection
- `MassAssignmentGuard` - Mass assignment protection
- `DeserializationGuard` - Unsafe deserialization detection
- `NoSqlInjectionGuard` - NoSQL injection detection
- `GraphQLGuard` - GraphQL abuse prevention
- `AnomalyGuard` - Behavioral anomaly detection

### Performance
- `BloomFilter` - Probabilistic pattern pre-screening
- `JitWarmer` - PCRE JIT optimization
- `LazyGuardResolver` - Deferred guard instantiation
- `StreamingInspector` - Chunk-based inspection
- `SharedMemoryStore` - Inter-worker state sharing

### Integrations
- `TelescopeIntegration` - Laravel Telescope support
- `PulseIntegration` - Laravel Pulse dashboards
- `OpenApiValidator` - OpenAPI/Swagger validation

### Analytics
- `AttackFingerprinter` - Attack signature generation
- `StixExporter` - STIX 2.1 threat intelligence
- `GeoIpCorrelator` - Geographic IP analysis
- `TrendAnalyzer` - Trend detection and forecasting
- `ComplianceReporter` - Compliance report generation

### Debug
- `DebugExplainer` - Detailed inspection explanations

### HTTP
- `HealthCheckController` - Health check endpoints
