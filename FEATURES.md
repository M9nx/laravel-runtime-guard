# Laravel Runtime Guard - Features

> Comprehensive runtime security inspection for Laravel applications.

## Version History

- **v1.0** - Core Guards, Pipeline System, Middleware, Reporters
- **v2.0** - Advanced Guards, Performance Optimization, DX Tools, Analytics
- **v3.0** - Resilience Patterns, Enterprise Security, Notifications, SIEM Integration

---

## Table of Contents

- [Security Guards](#security-guards)
- [Resilience Patterns](#resilience-patterns)
- [Performance Optimization](#performance-optimization)
- [Analytics & Intelligence](#analytics--intelligence)
- [Notifications & Integration](#notifications--integration)
- [Developer Experience](#developer-experience)

---

## Security Guards

### Core Guards (v1.0)

| Guard | Description | Priority |
|-------|-------------|----------|
| `SqlInjectionGuard` | Detects SQL injection patterns in input | 100 |
| `CommandInjectionGuard` | Detects shell command injection | 95 |
| `XssGuard` | Detects cross-site scripting payloads | 90 |
| `FileOperationGuard` | Detects path traversal & file inclusion | 85 |

### Advanced Guards (v2.0)

| Guard | Description | Priority |
|-------|-------------|----------|
| `SsrfGuard` | Server-side request forgery detection | 80 |
| `DeserializationGuard` | Unsafe deserialization detection | 92 |
| `NoSqlInjectionGuard` | MongoDB/NoSQL injection patterns | 88 |
| `MassAssignmentGuard` | Mass assignment protection | 75 |
| `GraphQLGuard` | GraphQL depth/complexity limiting | 70 |
| `AnomalyGuard` | Statistical anomaly detection | 50 |

### Enterprise Guards (v3.0)

| Guard | Description | Priority |
|-------|-------------|----------|
| `TimingShieldGuard` | Timing attack detection & protection | 99 |
| `RequestSignatureGuard` | HMAC request signature validation | 98 |
| `CredentialStuffingGuard` | Credential stuffing detection | 93 |
| `SessionIntegrityGuard` | Session hijacking detection | 91 |
| `JwtGuard` | JWT algorithm confusion & abuse | 89 |
| `BotBehaviorGuard` | Automated traffic detection | 60 |

---

## Resilience Patterns

### Circuit Breaker (v3.0)

Implements the circuit breaker pattern for guards to prevent cascading failures.

```php
use M9nx\RuntimeGuard\Resilience\CircuitBreaker;

$breaker = app(CircuitBreaker::class);

// States: CLOSED → OPEN → HALF_OPEN → CLOSED
$breaker->call('guard-name', function() {
    // Guarded operation
});

$breaker->getState('guard-name'); // 'closed', 'open', 'half_open'
```

**Configuration:**
```php
'resilience' => [
    'circuit_breaker' => [
        'enabled' => true,
        'failure_threshold' => 5,     // Open after 5 failures
        'recovery_timeout' => 30,      // Try recovery after 30s
        'half_open_requests' => 3,     // Test with 3 requests
    ],
],
```

### Load Shedding (v3.0)

Adaptive load shedding based on system resources with tiered guard priorities.

```php
use M9nx\RuntimeGuard\Resilience\LoadShedder;

$shedder = app(LoadShedder::class);

// Get guards to run based on current load
$guards = $shedder->filterGuards($allGuards);

// Check system health
$health = $shedder->getSystemHealth();
// ['cpu' => 45.5, 'memory' => 62.3, 'tier' => 'critical']
```

**Configuration:**
```php
'load_shedding' => [
    'enabled' => true,
    'cpu_threshold' => 80,
    'memory_threshold' => 85,
    'guard_tiers' => [
        'critical' => ['sql-injection', 'command-injection'],
        'high' => ['ssrf', 'credential-stuffing'],
        'medium' => ['xss', 'session-integrity'],
        'low' => ['anomaly', 'bot-behavior'],
    ],
],
```

---

## Performance Optimization

### Bloom Filter (v2.0)

Fast probabilistic pre-screening for known attack patterns.

```php
use M9nx\RuntimeGuard\Performance\BloomFilter;

$filter = app(BloomFilter::class);
$filter->add("known-attack-pattern");

if ($filter->mightContain($input)) {
    // Run full inspection
}
```

### Request Fingerprint (v3.0)

Memoized request fingerprinting for deduplication.

```php
use M9nx\RuntimeGuard\Support\RequestFingerprint;

$fp = app(RequestFingerprint::class);
$hash = $fp->compute($request);

// Memoized - same request returns cached hash
$fp->get($request); // Returns existing or computes
```

### Ring Buffer (v3.0)

Zero-allocation circular buffer for high-frequency event storage.

```php
use M9nx\RuntimeGuard\Support\RingBuffer;

$buffer = new RingBuffer(1000);
$buffer->push(['event' => 'threat', 'time' => now()]);

// Get recent events
$recent = $buffer->getAll();
$last10 = $buffer->slice(-10);
```

### Additional Performance Features

- **JIT Warmer** - Pre-compile regex patterns on boot
- **Lazy Guard Resolver** - Defer guard instantiation
- **Streaming Inspector** - Process large inputs in chunks
- **Shared Memory Store** - Octane/Swoole compatibility

---

## Analytics & Intelligence

### Risk Scoring Engine (v3.0)

Dynamic risk scoring with adaptive thresholds.

```php
use M9nx\RuntimeGuard\Analytics\RiskScoringEngine;

$engine = app(RiskScoringEngine::class);

$score = $engine->calculateScore('ip:192.168.1.1', [
    'violation' => ['guard' => 'sql_injection'],
    'request_rate' => 50,
    'geo_data' => ['country' => 'US'],
]);

$score->score;        // 75.5
$score->level;        // 'high'
$score->shouldBlock(); // true
$score->factors;      // ['current_violation' => 20, ...]
```

### Attack Chain Reconstructor (v3.0)

Reconstructs multi-stage attack patterns.

```php
use M9nx\RuntimeGuard\Analytics\AttackChainReconstructor;

$reconstructor = app(AttackChainReconstructor::class);
$reconstructor->recordEvent($event);

$chains = $reconstructor->getChains('192.168.1.1');
// [
//   'id' => 'chain-xxx',
//   'pattern' => 'credential_attack',
//   'stages' => ['enumeration', 'credential_stuffing', 'account_takeover'],
//   'confidence' => 0.85
// ]
```

### Additional Analytics

- **Attack Fingerprinter** - Unique attack signatures
- **STIX Exporter** - Threat intelligence format
- **GeoIP Correlator** - Geographic analysis
- **Trend Analyzer** - Historical patterns
- **Compliance Reporter** - PCI-DSS, OWASP, SOC2

---

## Notifications & Integration

### Webhook Dispatcher (v3.0)

Multi-endpoint webhook notifications with batching.

```php
use M9nx\RuntimeGuard\Notifications\WebhookDispatcher;

$dispatcher = app(WebhookDispatcher::class);

$dispatcher->dispatch([
    'type' => 'threat_detected',
    'guard' => 'sql-injection',
    'severity' => 'critical',
    'payload' => $threat,
]);

// Formats: json, slack, discord, pagerduty, teams
```

**Configuration:**
```php
'notifications' => [
    'webhooks' => [
        'enabled' => true,
        'endpoints' => [
            [
                'url' => env('SLACK_WEBHOOK_URL'),
                'format' => 'slack',
                'min_severity' => 'high',
            ],
            [
                'url' => env('PAGERDUTY_URL'),
                'format' => 'pagerduty',
                'min_severity' => 'critical',
            ],
        ],
    ],
],
```

### SIEM Connector (v3.0)

Enterprise SIEM integration with multiple formats.

```php
use M9nx\RuntimeGuard\Integrations\SiemConnector;

$siem = app(SiemConnector::class);
$siem->send($event);

// Supported formats:
// - CEF (Common Event Format)
// - LEEF (Log Event Extended Format)
// - Splunk HEC
// - Elastic Common Schema
// - JSON
```

**Configuration:**
```php
'siem' => [
    'enabled' => true,
    'driver' => 'splunk',
    'endpoint' => env('SPLUNK_HEC_URL'),
    'token' => env('SPLUNK_TOKEN'),
    'index' => 'security',
],
```

### Plugin Architecture (v3.0)

Extensible guard system with auto-discovery.

```php
use M9nx\RuntimeGuard\Plugins\PluginManager;

$plugins = app(PluginManager::class);

// Auto-discovers from composer packages:
// {
//   "extra": {
//     "runtime-guard": {
//       "guards": {
//         "custom-guard": "Vendor\\Package\\CustomGuard"
//       }
//     }
//   }
// }

$plugins->register('my-guard', MyCustomGuard::class);
$plugins->all(); // All registered plugins
```

---

## Developer Experience

### Security Audit Command (v3.0)

Static analysis for security issues.

```bash
# Full audit
php artisan runtime-guard:audit

# Specific directory
php artisan runtime-guard:audit app/Http

# SARIF output for CI/CD
php artisan runtime-guard:audit --format=sarif --output=report.sarif

# Filter by severity
php artisan runtime-guard:audit --min-severity=high
```

**Detected Issues:**
- SQL Injection (raw queries, string interpolation)
- XSS (unescaped output, raw HTML)
- Command Injection (shell_exec, passthru)
- File Operations (path traversal patterns)
- Deserialization (unserialize usage)
- Weak Cryptography (MD5, SHA1)
- Mass Assignment (no fillable/guarded)
- CSRF (missing middleware)
- Information Disclosure (error output)

### Additional DX Tools

- **`php artisan runtime-guard:status`** - System status
- **`php artisan runtime-guard:test`** - Test guards with samples
- **`php artisan runtime-guard:toggle`** - Enable/disable guards
- **`php artisan make:guard`** - Generate custom guards
- **Health Check Endpoint** - `/_runtime-guard/health`

---

## Quick Start

### Installation

```bash
composer require m9nx/laravel-runtime-guard
php artisan vendor:publish --tag=runtime-guard-config
```

### Basic Usage

```php
// Middleware (automatic)
Route::middleware('runtime-guard')->group(function () {
    // Protected routes
});

// Manual inspection
use M9nx\RuntimeGuard\GuardManager;

$manager = app(GuardManager::class);
$result = $manager->inspect($userInput);

if ($result->hasThreat()) {
    // Handle threat
}
```

### Configuration

See `config/runtime-guard.php` for all options.

---

## Guard Configuration Reference

```php
// config/runtime-guard.php
'guards' => [
    'sql-injection' => [
        'enabled' => true,
        'priority' => 100,
    ],
    
    'credential-stuffing' => [
        'enabled' => true,
        'ip_velocity_threshold' => 10,
        'user_velocity_threshold' => 5,
        'velocity_window' => 300,
        'enable_hibp_check' => false,
    ],
    
    'jwt' => [
        'enabled' => false,
        'allowed_algorithms' => ['RS256', 'ES256'],
        'reject_none_algorithm' => true,
        'detect_replay' => true,
    ],
    
    'bot-behavior' => [
        'enabled' => true,
        'enable_honeypot' => true,
        'honeypot_fields' => ['website', '_honey'],
    ],
    
    'timing-shield' => [
        'enabled' => true,
        'add_response_jitter' => true,
        'detect_timing_probes' => true,
    ],
],
```

---

## Version 3.0 Summary

### New Components

| Category | Components |
|----------|------------|
| **Guards** | TimingShield, RequestSignature, CredentialStuffing, SessionIntegrity, JWT, BotBehavior |
| **Resilience** | CircuitBreaker, LoadShedder |
| **Support** | RingBuffer, RequestFingerprint |
| **Analytics** | RiskScoringEngine, AttackChainReconstructor |
| **Notifications** | WebhookDispatcher, SendWebhookJob |
| **Integrations** | SiemConnector, PluginManager |
| **Commands** | SecurityAuditCommand |

### Breaking Changes

None. v3.0 is fully backward compatible with v2.0.

### Migration Guide

1. Update composer: `composer update m9nx/laravel-runtime-guard`
2. Publish new config: `php artisan vendor:publish --tag=runtime-guard-config --force`
3. Review new guard configurations in `config/runtime-guard.php`
4. Enable desired v3.0 features

---

## Support

- **Documentation**: [GitHub Wiki](https://github.com/m9nx/laravel-runtime-guard/wiki)
- **Issues**: [GitHub Issues](https://github.com/m9nx/laravel-runtime-guard/issues)
- **Security**: security@example.com
