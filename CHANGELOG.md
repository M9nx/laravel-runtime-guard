# Changelog

All notable changes to `laravel-runtime-guard` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-06

### Added
- **Core Architecture**
  - `GuardInterface`, `GuardResultInterface`, `GuardManagerInterface`, `ReporterInterface` contracts
  - `ThreatLevel` enum (NONE, LOW, MEDIUM, HIGH, CRITICAL)
  - `AbstractGuard` base class for custom guard development
  - `GuardManager` central orchestration engine
  - `GuardResult` immutable value object

- **Security Guards**
  - `SqlInjectionGuard` - UNION, boolean-based, time-based, stacked queries detection
  - `XssGuard` - Script tags, event handlers, DOM-based XSS, encoded payloads
  - `CommandInjectionGuard` - Shell metacharacters, command chaining
  - `FileOperationGuard` - Path traversal, null bytes, protocol wrappers
  - `SsrfGuard` - Internal IPs, cloud metadata endpoints, DNS rebinding
  - `MassAssignmentGuard` - Dangerous field protection
  - `DeserializationGuard` - PHP object injection, gadget chains
  - `NoSqlInjectionGuard` - MongoDB operators, JSON-encoded attacks
  - `GraphqlGuard` - Query depth limits, complexity analysis
  - `JwtGuard` - Algorithm confusion, replay attacks
  - `BotBehaviorGuard` - Automation detection
  - `SessionIntegrityGuard` - Session hijacking detection
  - `AnomalyGuard` - Behavioral anomaly detection

- **Laravel Integration**
  - `RuntimeGuardServiceProvider` with auto-discovery
  - `RuntimeGuard` facade
  - `runtime-guard` middleware
  - `InspectsInput` controller trait
  - `#[GuardProfile]` and `#[SkipGuard]` PHP attributes

- **Reporters**
  - `LogReporter` for Laravel logging
  - `DatabaseReporter` for persistent storage
  - `SlackReporter` for real-time alerts

- **Performance**
  - Tiered inspection (quick scan + deep analysis)
  - LRU deduplication cache
  - Request sampling
  - Bloom filter pre-screening
  - Lazy guard resolution
  - Streaming inspection for large payloads

- **Developer Tools**
  - `php artisan runtime-guard:list` - List all guards
  - `php artisan runtime-guard:test` - Test guards with sample input
  - `php artisan runtime-guard:status` - System status
  - `php artisan runtime-guard:toggle` - Enable/disable guards
  - `php artisan runtime-guard:make-guard` - Generate custom guards
  - `php artisan runtime-guard:security-audit` - Run security audit

- **Testing**
  - `RuntimeGuard::fake()` for testing
  - Pest PHP test suite
  - PHPStan static analysis (Level 5)

### Security
- Immutable result objects prevent tampering
- Clear separation between detection and response
- No external dependencies for core functionality
