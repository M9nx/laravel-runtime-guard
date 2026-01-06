# Changelog

All notable changes to `laravel-runtime-guard` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial package architecture
- Core contracts: `GuardInterface`, `GuardResultInterface`, `GuardManagerInterface`, `ReporterInterface`
- `ThreatLevel` enum with severity classification
- `AbstractGuard` base class for easy guard creation
- `GuardManager` for central guard orchestration
- `GuardResult` immutable value object
- `RuntimeGuardServiceProvider` with auto-discovery
- `RuntimeGuard` facade
- `LogReporter` for logging security events
- `SqlInjectionGuard` as reference implementation
- Configuration file with extensive options
- Exception classes: `RuntimeGuardException`, `GuardNotFoundException`, `ThreatDetectedException`
- Comprehensive documentation
- Test suite with Pest PHP
- PHPStan static analysis configuration

### Security
- Package foundation follows security best practices
- Immutable result objects prevent tampering
- Clear separation between detection and response
