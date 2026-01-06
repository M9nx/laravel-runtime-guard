<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | RuntimeGuard Master Switch
    |--------------------------------------------------------------------------
    |
    | This option controls whether RuntimeGuard is enabled globally. When
    | disabled, all guards will be bypassed and no inspections will run.
    |
    */

    'enabled' => env('RUNTIME_GUARD_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Dry Run Mode
    |--------------------------------------------------------------------------
    |
    | When enabled, guards will run but no actions will be taken. Useful
    | for testing and initial deployment to observe behavior without risk.
    |
    */

    'dry_run' => env('RUNTIME_GUARD_DRY_RUN', false),

    /*
    |--------------------------------------------------------------------------
    | Response Mode
    |--------------------------------------------------------------------------
    |
    | Determines how RuntimeGuard responds when a threat is detected:
    |
    | - "block": Throws ThreatDetectedException to halt execution
    | - "log": Logs the threat but allows execution to continue
    | - "silent": Records internally but takes no visible action
    |
    */

    'mode' => env('RUNTIME_GUARD_MODE', 'log'),

    /*
    |--------------------------------------------------------------------------
    | Minimum Threat Level for Blocking
    |--------------------------------------------------------------------------
    |
    | When mode is "block", this determines the minimum threat level that
    | will trigger blocking. Options: none, low, medium, high, critical
    |
    */

    'block_threshold' => env('RUNTIME_GUARD_BLOCK_THRESHOLD', 'high'),

    /*
    |--------------------------------------------------------------------------
    | Pipeline Configuration
    |--------------------------------------------------------------------------
    |
    | Controls how guards are executed in the inspection pipeline.
    |
    */

    'pipeline' => [

        // Strategy: 'full' (run all), 'short_circuit' (stop on first threat),
        //           'threshold' (stop when threat level reached)
        'strategy' => env('RUNTIME_GUARD_PIPELINE_STRATEGY', 'full'),

        // For threshold strategy: stop when this level is reached
        'threshold_level' => 'high',

        // Enable tiered inspection (quick scan then deep inspect)
        'tiered' => true,

        // Timeout per guard in milliseconds (0 = no timeout)
        'guard_timeout_ms' => 100,

        // Total pipeline timeout in milliseconds (0 = no timeout)
        'total_timeout_ms' => 500,

    ],

    /*
    |--------------------------------------------------------------------------
    | Performance Optimization
    |--------------------------------------------------------------------------
    |
    | Settings to optimize performance for high-traffic applications.
    |
    */

    'performance' => [

        // Bloom filter for fast pattern pre-screening
        'bloom_filter' => [
            'enabled' => env('RUNTIME_GUARD_BLOOM_ENABLED', true),
            'expected_items' => 10000,
            'false_positive_rate' => 0.01,
        ],

        // JIT pattern warming on boot
        'jit_warming' => [
            'enabled' => env('RUNTIME_GUARD_JIT_WARMING', true),
            'warm_on_boot' => false,  // Warm during service boot
        ],

        // Lazy guard resolution (defer until first use)
        'lazy_guards' => [
            'enabled' => env('RUNTIME_GUARD_LAZY_GUARDS', true),
        ],

        // Streaming inspection for large inputs
        'streaming' => [
            'enabled' => true,
            'chunk_size' => 8192,
            'max_input_size' => 10485760, // 10MB
        ],

        // Shared memory for Octane/Swoole
        'shared_memory' => [
            'enabled' => env('RUNTIME_GUARD_SHARED_MEMORY', false),
            'driver' => 'auto', // 'swoole', 'apcu', 'array'
        ],

        // Deduplication: skip inspection for recently-seen identical inputs
        'deduplication' => [
            'enabled' => env('RUNTIME_GUARD_DEDUP_ENABLED', true),
            'max_entries' => 1000,  // Max cache entries
            'ttl' => 60,            // Cache TTL in seconds
        ],

        // Sampling: only inspect a percentage of requests
        'sampling' => [
            'enabled' => env('RUNTIME_GUARD_SAMPLING_ENABLED', false),
            'rate' => 1.0,                      // 1.0 = 100%, 0.1 = 10%
            'always_sample_suspicious' => true, // Always inspect if looks suspicious
            'always_sample_routes' => [],       // Routes to always inspect
        ],

        // Input limits: prevent DoS via large inputs
        'limits' => [
            'max_input_bytes' => 65536,    // 64KB max input size
            'max_array_depth' => 10,       // Max nesting depth
            'max_array_items' => 1000,     // Max array elements
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Correlation Engine
    |--------------------------------------------------------------------------
    |
    | Track and correlate multiple events to detect coordinated attacks.
    |
    */

    'correlation' => [

        'enabled' => env('RUNTIME_GUARD_CORRELATION_ENABLED', true),

        // Time window for correlating events (seconds)
        'window_seconds' => 300,

        // Alert if this many events occur within window
        'alert_threshold' => 5,

        // Track by these identifiers
        'track_by' => ['ip', 'user_id', 'session_id'],

        // Store backend: 'memory', 'cache', 'redis'
        'store' => env('RUNTIME_GUARD_CORRELATION_STORE', 'cache'),

    ],

    /*
    |--------------------------------------------------------------------------
    | Progressive Enforcement
    |--------------------------------------------------------------------------
    |
    | Escalate responses based on repeated violations.
    |
    */

    'progressive' => [

        'enabled' => env('RUNTIME_GUARD_PROGRESSIVE_ENABLED', true),

        // Escalation thresholds (events within window)
        'thresholds' => [
            'log' => 1,     // Start logging at 1 event
            'alert' => 3,   // Alert after 3 events
            'block' => 5,   // Block after 5 events
        ],

        // Time window for counting events (seconds)
        'window_seconds' => 600,

        // Cool-down period after blocking (seconds)
        'cooldown_seconds' => 3600,

    ],

    /*
    |--------------------------------------------------------------------------
    | Registered Guards
    |--------------------------------------------------------------------------
    |
    | List of guard classes to register. Each guard can have its own
    | configuration. Guards are resolved from the container, allowing
    | for dependency injection.
    |
    */

    'guards' => [

        'sql-injection' => [
            'class' => \M9nx\RuntimeGuard\Guards\SqlInjectionGuard::class,
            'enabled' => true,
            'priority' => 100,
            'patterns' => [],  // Additional patterns to check
        ],

        'xss' => [
            'class' => \M9nx\RuntimeGuard\Guards\XssGuard::class,
            'enabled' => true,
            'priority' => 90,
        ],

        'command-injection' => [
            'class' => \M9nx\RuntimeGuard\Guards\CommandInjectionGuard::class,
            'enabled' => true,
            'priority' => 95,
        ],

        'file-operation' => [
            'class' => \M9nx\RuntimeGuard\Guards\FileOperationGuard::class,
            'enabled' => true,
            'priority' => 85,
        ],

        'ssrf' => [
            'class' => \M9nx\RuntimeGuard\Guards\SsrfGuard::class,
            'enabled' => true,
            'priority' => 80,
            'blocked_hosts' => [],      // Additional hosts to block
            'allowed_hosts' => [],       // Whitelist (bypass checks)
            'block_private_ips' => true,
            'block_metadata_endpoints' => true,
        ],

        'mass-assignment' => [
            'class' => \M9nx\RuntimeGuard\Guards\MassAssignmentGuard::class,
            'enabled' => true,
            'priority' => 75,
            'dangerous_fields' => [],    // Additional fields to flag
            'allowed_fields' => [],      // Fields to ignore
        ],

        'deserialization' => [
            'class' => \M9nx\RuntimeGuard\Guards\DeserializationGuard::class,
            'enabled' => true,
            'priority' => 92,
            'block_phar' => true,
            'block_base64_serialized' => true,
        ],

        'nosql-injection' => [
            'class' => \M9nx\RuntimeGuard\Guards\NoSqlInjectionGuard::class,
            'enabled' => true,
            'priority' => 88,
        ],

        'graphql' => [
            'class' => \M9nx\RuntimeGuard\Guards\GraphQLGuard::class,
            'enabled' => false, // Enable if using GraphQL
            'priority' => 70,
            'max_depth' => 10,
            'max_complexity' => 100,
            'max_aliases' => 10,
            'max_directives' => 5,
            'allow_introspection' => false,
        ],

        'anomaly' => [
            'class' => \M9nx\RuntimeGuard\Guards\AnomalyGuard::class,
            'enabled' => false, // Enable after baseline is established
            'priority' => 50,
            'learning_mode' => true,  // Start in learning mode
            'deviation_threshold' => 3.0,
            'tracked_metrics' => [
                'request_size',
                'parameter_count',
                'input_entropy',
            ],
        ],

        /*
        |----------------------------------------------------------------------
        | v3.0 Guards
        |----------------------------------------------------------------------
        */

        'credential-stuffing' => [
            'class' => \M9nx\RuntimeGuard\Guards\CredentialStuffingGuard::class,
            'enabled' => true,
            'priority' => 93,
            'ip_velocity_threshold' => 10,        // Max attempts per IP/window
            'user_velocity_threshold' => 5,       // Max attempts per user/window
            'velocity_window' => 300,             // 5 minutes
            'enable_hibp_check' => false,         // Check Have I Been Pwned
            'hibp_threshold' => 5,                // Block if seen > N times
            'detect_distributed' => true,         // Detect distributed attacks
        ],

        'session-integrity' => [
            'class' => \M9nx\RuntimeGuard\Guards\SessionIntegrityGuard::class,
            'enabled' => true,
            'priority' => 91,
            'fingerprint_fields' => ['User-Agent', 'Accept-Language'],
            'detect_geo_jump' => true,
            'impossible_travel_km' => 500,        // km per hour threshold
            'detect_concurrent' => true,
            'max_concurrent_sessions' => 3,
        ],

        'jwt' => [
            'class' => \M9nx\RuntimeGuard\Guards\JwtGuard::class,
            'enabled' => false, // Enable if using JWT
            'priority' => 89,
            'allowed_algorithms' => ['RS256', 'RS384', 'RS512', 'ES256'],
            'reject_none_algorithm' => true,
            'reject_symmetric_with_public_key' => true,
            'detect_replay' => true,
            'token_replay_window' => 300,
            'max_clock_skew' => 60,
            'detect_jku_injection' => true,
            'trusted_issuers' => [],
        ],

        'bot-behavior' => [
            'class' => \M9nx\RuntimeGuard\Guards\BotBehaviorGuard::class,
            'enabled' => true,
            'priority' => 60,
            'request_timing_threshold' => 0.1,    // 100ms
            'navigation_anomaly_threshold' => 0.8,
            'enable_honeypot' => true,
            'honeypot_fields' => ['website', 'url', 'email_confirm', '_honey'],
            'check_headless_indicators' => true,
            'check_automation_indicators' => true,
            'session_window' => 3600,
        ],

        'request-signature' => [
            'class' => \M9nx\RuntimeGuard\Guards\RequestSignatureGuard::class,
            'enabled' => false, // Enable for API signature validation
            'priority' => 98,
            'signature_header' => 'X-Signature',
            'timestamp_header' => 'X-Timestamp',
            'nonce_header' => 'X-Nonce',
            'timestamp_tolerance' => 300,
            'default_algorithm' => 'sha256',
            'require_timestamp' => true,
            'require_nonce' => false,
            'secrets' => [
                // 'key-id' => env('API_SIGNATURE_SECRET'),
            ],
        ],

        'timing-shield' => [
            'class' => \M9nx\RuntimeGuard\Guards\TimingShieldGuard::class,
            'enabled' => true,
            'priority' => 99,
            'add_response_jitter' => true,
            'min_jitter_ms' => 5,
            'max_jitter_ms' => 50,
            'detect_timing_probes' => true,
            'probe_detection_window' => 60,
            'probe_threshold' => 20,
            'enforce_constant_time' => false,
            'target_response_time_ms' => 200,
            'sensitive_endpoints' => [
                '/api/login',
                '/api/auth',
                '/api/verify',
                '/api/password',
                '/api/token',
            ],
        ],

        /*
        |----------------------------------------------------------------------
        | v4.0 Ultimate Edition Guards
        |----------------------------------------------------------------------
        */

        'behavioral-fingerprint' => [
            'class' => \M9nx\RuntimeGuard\Guards\BehavioralFingerprintGuard::class,
            'enabled' => true,
            'priority' => 65,
            'features' => ['timing', 'navigation', 'interaction', 'mouse', 'keyboard'],
            'deviation_threshold' => 0.3,
            'min_samples' => 5,
            'session_window' => 3600,
        ],

        'payload-obfuscation' => [
            'class' => \M9nx\RuntimeGuard\Guards\PayloadObfuscationGuard::class,
            'enabled' => true,
            'priority' => 87,
            'detect_base64' => true,
            'detect_hex' => true,
            'detect_unicode' => true,
            'detect_html_entities' => true,
            'max_decode_depth' => 5,
            'entropy_threshold' => 4.5,
        ],

        'api-abuse' => [
            'class' => \M9nx\RuntimeGuard\Guards\ApiAbuseGuard::class,
            'enabled' => true,
            'priority' => 72,
            'rate_limits' => [
                'default' => ['requests' => 100, 'window' => 60],
                'auth' => ['requests' => 10, 'window' => 60],
                'sensitive' => ['requests' => 20, 'window' => 60],
            ],
            'detect_enumeration' => true,
            'detect_parameter_tampering' => true,
            'detect_response_scraping' => true,
        ],

        'prototype-pollution' => [
            'class' => \M9nx\RuntimeGuard\Guards\PrototypePollutionGuard::class,
            'enabled' => true,
            'priority' => 86,
            'blocked_keys' => ['__proto__', 'constructor', 'prototype'],
            'scan_depth' => 10,
            'strict_mode' => true,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Route Profiles
    |--------------------------------------------------------------------------
    |
    | Define guard configurations for specific routes or route patterns.
    | Profiles allow different guard settings for different parts of your app.
    |
    */

    'profiles' => [

        'default' => [
            'guards' => '*',       // All guards
            'mode' => null,        // Use global mode
            'sampling_rate' => null,
        ],

        'api' => [
            'guards' => ['sql-injection', 'command-injection'],
            'mode' => 'log',
            'sampling_rate' => 1.0,
        ],

        'admin' => [
            'guards' => '*',
            'mode' => 'block',
            'sampling_rate' => 1.0,
        ],

        'public' => [
            'guards' => ['sql-injection', 'xss'],
            'mode' => 'log',
            'sampling_rate' => 0.5,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Profile Route Mapping
    |--------------------------------------------------------------------------
    |
    | Map URL patterns or route names to profiles.
    |
    */

    'profile_routes' => [

        // Pattern => Profile name
        'api/*' => 'api',
        'admin/*' => 'admin',
        'webhook/*' => null,  // null = skip inspection

    ],

    /*
    |--------------------------------------------------------------------------
    | Feature Flags
    |--------------------------------------------------------------------------
    |
    | Runtime toggles for individual guards without deployment.
    |
    */

    'feature_flags' => [

        'enabled' => env('RUNTIME_GUARD_FEATURE_FLAGS_ENABLED', true),

        // Storage: 'config', 'cache', 'database'
        'store' => env('RUNTIME_GUARD_FLAGS_STORE', 'cache'),

        // Cache key prefix for flag storage
        'cache_prefix' => 'runtime_guard_flags',

        // Default state for guards not explicitly configured
        'default_enabled' => true,

        // Per-guard overrides (takes precedence over store)
        'overrides' => [
            // 'sql-injection' => true,
            // 'experimental-guard' => false,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Resilience
    |--------------------------------------------------------------------------
    |
    | v3.0 resilience patterns for high-availability scenarios.
    |
    */

    'resilience' => [

        'circuit_breaker' => [
            'enabled' => env('RUNTIME_GUARD_CIRCUIT_BREAKER', true),
            'failure_threshold' => 5,
            'recovery_timeout' => 30,
            'half_open_requests' => 3,
        ],

        'load_shedding' => [
            'enabled' => env('RUNTIME_GUARD_LOAD_SHEDDING', false),
            'cpu_threshold' => 80,
            'memory_threshold' => 85,
            'check_interval' => 1,
            'guard_tiers' => [
                'critical' => ['sql-injection', 'command-injection', 'deserialization'],
                'high' => ['ssrf', 'file-operation', 'credential-stuffing'],
                'medium' => ['xss', 'mass-assignment', 'session-integrity'],
                'low' => ['anomaly', 'bot-behavior', 'graphql'],
            ],
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Notifications
    |--------------------------------------------------------------------------
    |
    | v3.0 webhook notification system for real-time alerting.
    |
    */

    'notifications' => [

        'webhooks' => [
            'enabled' => env('RUNTIME_GUARD_WEBHOOKS', false),
            'endpoints' => [
                // [
                //     'url' => env('RUNTIME_GUARD_WEBHOOK_URL'),
                //     'secret' => env('RUNTIME_GUARD_WEBHOOK_SECRET'),
                //     'min_severity' => 'high',
                //     'format' => 'json', // json, slack, discord, pagerduty, teams
                // ],
            ],
            'batch_size' => 10,
            'batch_timeout' => 5,
            'retry_times' => 3,
            'retry_delay' => 60,
        ],

        'siem' => [
            'enabled' => env('RUNTIME_GUARD_SIEM', false),
            'driver' => 'splunk', // cef, leef, splunk, elastic, json
            'endpoint' => env('RUNTIME_GUARD_SIEM_ENDPOINT'),
            'token' => env('RUNTIME_GUARD_SIEM_TOKEN'),
            'index' => env('RUNTIME_GUARD_SIEM_INDEX', 'security'),
            'batch_size' => 100,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Plugins
    |--------------------------------------------------------------------------
    |
    | v3.0 plugin architecture for extensible guards.
    |
    */

    'plugins' => [

        'auto_discovery' => true,
        'trusted_vendors' => [],  // Empty = trust all, or list specific vendors
        'plugin_directory' => null,  // Custom directory for local plugins

    ],

    /*
    |--------------------------------------------------------------------------
    | Risk Scoring
    |--------------------------------------------------------------------------
    |
    | v3.0 dynamic risk scoring engine configuration.
    |
    */

    'risk_scoring' => [

        'enabled' => env('RUNTIME_GUARD_RISK_SCORING', true),
        'decay_rate' => 0.1,
        'max_history' => 100,
        'adaptive_threshold' => true,
        'baseline_period' => 3600,

        'factor_weights' => [
            'guard_violation' => 20,
            'repeated_violation' => 30,
            'velocity_anomaly' => 25,
            'geo_anomaly' => 15,
            'pattern_match' => 35,
            'time_anomaly' => 10,
            'fingerprint_change' => 20,
            'known_bad_actor' => 50,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Reporters
    |--------------------------------------------------------------------------
    |
    | Reporters handle what happens after a threat is detected. Multiple
    | reporters can be active simultaneously.
    |
    */

    'reporters' => [

        'log' => [
            'enabled' => true,
            'channel' => env('RUNTIME_GUARD_LOG_CHANNEL', 'stack'),
            'min_level' => 'low',  // Minimum threat level to report
        ],

        'database' => [
            'enabled' => env('RUNTIME_GUARD_DB_REPORTER', false),
            'connection' => null,  // null = default connection
            'table' => 'runtime_guard_events',
            'min_level' => 'medium',
            'retention_days' => 30,  // Auto-cleanup old records
        ],

        'async' => [
            'enabled' => env('RUNTIME_GUARD_ASYNC_REPORTER', false),
            'queue' => env('RUNTIME_GUARD_QUEUE', 'default'),
            'connection' => null,  // null = default queue connection
        ],

        // 'webhook' => [
        //     'enabled' => false,
        //     'url' => env('RUNTIME_GUARD_WEBHOOK_URL'),
        //     'min_level' => 'high',
        //     'timeout' => 5,
        // ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Exclusions
    |--------------------------------------------------------------------------
    |
    | Define paths, routes, or patterns that should be excluded from
    | runtime inspection.
    |
    */

    'exclusions' => [

        // URI paths to exclude (supports wildcards)
        'paths' => [
            '_debugbar/*',
            'telescope/*',
            'horizon/*',
            // 'api/webhooks/*',
            // 'health',
        ],

        // Route names to exclude
        'routes' => [
            // 'webhooks.stripe',
        ],

        // IP addresses to exclude (trusted sources)
        'ips' => [
            // '127.0.0.1',
        ],

        // User agents to exclude (careful with this!)
        'user_agents' => [
            // 'Googlebot',
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Middleware Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for the RuntimeGuard HTTP middleware.
    |
    */

    'middleware' => [

        // Automatically register middleware in web group
        'auto_register' => false,

        // What to inspect in requests
        'inspect_query' => true,
        'inspect_body' => true,
        'inspect_headers' => false,
        'inspect_cookies' => false,

        // Response on blocked request
        'block_response' => [
            'status' => 403,
            'message' => 'Request blocked by security policy',
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Request Inspection (Deprecated - use middleware config)
    |--------------------------------------------------------------------------
    */

    'request' => [
        'auto_inspect' => false,
        'inspect_query' => true,
        'inspect_body' => true,
        'inspect_headers' => false,
        'inspect_cookies' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Integrations
    |--------------------------------------------------------------------------
    |
    | Third-party tool integrations for enhanced observability.
    |
    */

    'integrations' => [

        'telescope' => [
            'enabled' => env('RUNTIME_GUARD_TELESCOPE', true),
            'record_levels' => ['low', 'medium', 'high', 'critical'],
        ],

        'pulse' => [
            'enabled' => env('RUNTIME_GUARD_PULSE', true),
        ],

        'openapi' => [
            'enabled' => env('RUNTIME_GUARD_OPENAPI', false),
            'spec_path' => base_path('openapi.yaml'),
            'skip_paths' => [
                '/health',
                '/metrics',
            ],
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Debug Mode
    |--------------------------------------------------------------------------
    |
    | Enable detailed explanations for guard decisions (development only).
    |
    */

    'debug' => [
        'enabled' => env('RUNTIME_GUARD_DEBUG', false),
        'explain_passes' => false,    // Explain why inputs passed
        'explain_threats' => true,    // Explain threat detections
        'log_timing' => true,         // Log guard execution times
    ],

    /*
    |--------------------------------------------------------------------------
    | Analytics
    |--------------------------------------------------------------------------
    |
    | Threat intelligence and analytics features.
    |
    */

    'analytics' => [

        'fingerprinting' => [
            'enabled' => env('RUNTIME_GUARD_FINGERPRINTING', true),
        ],

        'stix' => [
            'enabled' => env('RUNTIME_GUARD_STIX', false),
            'identity' => env('APP_NAME', 'RuntimeGuard'),
            'export_path' => storage_path('app/stix'),
        ],

        'geoip' => [
            'enabled' => env('RUNTIME_GUARD_GEOIP', false),
            'database_path' => storage_path('app/geoip/GeoLite2-City.mmdb'),
        ],

        'trends' => [
            'enabled' => env('RUNTIME_GUARD_TRENDS', true),
            'retention_hours' => 168,  // 7 days of hourly data
            'retention_days' => 90,    // 90 days of daily data
        ],

        'compliance' => [
            'enabled' => env('RUNTIME_GUARD_COMPLIANCE', false),
            'frameworks' => ['pci-dss', 'owasp', 'soc2'],
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Health Check
    |--------------------------------------------------------------------------
    |
    | Expose a health check endpoint for monitoring.
    |
    */

    'health_check' => [
        'enabled' => env('RUNTIME_GUARD_HEALTH_CHECK', true),
        'path' => '/_runtime-guard/health',
        'middleware' => [], // Add auth middleware if needed
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    |
    | Detailed logging configuration.
    |
    */

    'logging' => [
        'enabled' => env('RUNTIME_GUARD_LOGGING', true),
        'channel' => env('RUNTIME_GUARD_LOG_CHANNEL', 'stack'),
        'retention_days' => 90,
    ],

    /*
    |--------------------------------------------------------------------------
    | v4.0 Ultimate Edition - ML/AI Configuration
    |--------------------------------------------------------------------------
    |
    | Machine learning and artificial intelligence components for advanced
    | threat detection and pattern recognition.
    |
    */

    'ml' => [

        'anomaly_detector' => [
            'enabled' => env('RUNTIME_GUARD_ML_ANOMALY', true),
            'contamination' => 0.1,
            'min_samples' => 100,
            'features' => ['request_size', 'param_count', 'entropy', 'timing'],
        ],

        'pattern_learning' => [
            'enabled' => env('RUNTIME_GUARD_ML_PATTERNS', true),
            'min_support' => 0.05,
            'min_confidence' => 0.8,
            'max_pattern_length' => 5,
            'learning_window' => 86400, // 24 hours
        ],

        'threat_classifier' => [
            'enabled' => env('RUNTIME_GUARD_ML_CLASSIFIER', true),
            'model_path' => storage_path('app/runtime-guard/models'),
            'confidence_threshold' => 0.7,
            'categories' => [
                'injection', 'xss', 'rce', 'traversal', 'ssrf',
                'credential_stuffing', 'bot', 'dos', 'reconnaissance',
            ],
        ],

        'adaptive_threshold' => [
            'enabled' => env('RUNTIME_GUARD_ML_ADAPTIVE', true),
            'sensitivity' => 0.8,
            'learning_rate' => 0.1,
            'history_window' => 3600,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | v4.0 Ultimate Edition - Performance Optimizers
    |--------------------------------------------------------------------------
    |
    | Advanced performance optimization components for high-throughput
    | environments.
    |
    */

    'optimizer' => [

        'fusion' => [
            'enabled' => env('RUNTIME_GUARD_FUSION', true),
            'strategy' => 'adaptive', // 'parallel', 'sequential', 'adaptive'
            'max_batch_size' => 100,
        ],

        'async_executor' => [
            'enabled' => env('RUNTIME_GUARD_ASYNC_EXECUTOR', false),
            'pool_size' => 4,
            'timeout_ms' => 100,
            'use_fibers' => true, // PHP 8.1+ Fibers
        ],

        'incremental' => [
            'enabled' => env('RUNTIME_GUARD_INCREMENTAL', true),
            'checkpoint_interval' => 1000,
            'max_cached_states' => 10000,
        ],

        'resource_pool' => [
            'enabled' => env('RUNTIME_GUARD_RESOURCE_POOL', true),
            'max_memory_mb' => 128,
            'max_cpu_percent' => 10,
            'pool_sizes' => [
                'pattern_matchers' => 10,
                'validators' => 5,
                'analyzers' => 3,
            ],
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | v4.0 Ultimate Edition - Developer Tools
    |--------------------------------------------------------------------------
    |
    | Interactive tools for security testing, profiling, and rule development.
    |
    */

    'devtools' => [

        'playground' => [
            'enabled' => env('RUNTIME_GUARD_PLAYGROUND', false), // Dev only
            'max_executions' => 100,
            'allow_custom_guards' => false,
        ],

        'profiler' => [
            'enabled' => env('RUNTIME_GUARD_PROFILER', false), // Dev only
            'sample_rate' => 0.01, // 1% of requests
            'track_memory' => true,
            'track_io' => false,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | v4.0 Ultimate Edition - Multi-Tenant
    |--------------------------------------------------------------------------
    |
    | Secure tenant isolation and per-tenant security configuration for
    | SaaS and multi-tenant applications.
    |
    */

    'multi_tenant' => [

        'enabled' => env('RUNTIME_GUARD_MULTI_TENANT', false),

        'isolation' => [
            'strategy' => 'database', // 'database', 'cache_prefix', 'separate'
            'tenant_header' => 'X-Tenant-ID',
            'tenant_param' => 'tenant_id',
            'domain_mapping' => [],
        ],

        'rules' => [
            'inherit_global' => true,
            'allow_override' => ['mode', 'sampling_rate'],
            'deny_override' => ['enabled'],
        ],

        'intelligence' => [
            'sharing_level' => 'anonymized', // 'none', 'anonymized', 'full'
            'correlation_window' => 3600,
            'min_reports' => 3, // Min reports before sharing
        ],

        'quotas' => [
            'enabled' => true,
            'default_requests_per_minute' => 1000,
            'default_requests_per_hour' => 50000,
            'default_requests_per_day' => 500000,
            'enforcement' => 'soft', // 'soft', 'hard'
            'grace_percent' => 10,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | v4.0 Ultimate Edition - Observability
    |--------------------------------------------------------------------------
    |
    | Real-time monitoring, visualization, and alerting components.
    |
    */

    'observability' => [

        'metrics' => [
            'enabled' => env('RUNTIME_GUARD_METRICS', true),
            'flush_interval' => 60,
            'retention_hours' => 24,
            'export_format' => 'prometheus', // 'prometheus', 'statsd', 'json'
            'export_endpoint' => env('RUNTIME_GUARD_METRICS_ENDPOINT'),
        ],

        'heatmap' => [
            'enabled' => env('RUNTIME_GUARD_HEATMAP', true),
            'grid_size' => 100,
            'update_interval' => 300, // 5 minutes
            'types' => ['geographic', 'endpoint', 'temporal', 'vector'],
        ],

        'scorecard' => [
            'enabled' => env('RUNTIME_GUARD_SCORECARD', true),
            'calculation_interval' => 3600, // Hourly
            'categories' => [
                'threat_detection', 'guard_coverage', 'response_time',
                'false_positive_rate', 'configuration', 'compliance',
            ],
        ],

        'alert_correlator' => [
            'enabled' => env('RUNTIME_GUARD_ALERT_CORRELATOR', true),
            'time_window' => 300,
            'similarity_threshold' => 0.7,
            'deduplication_window' => 60,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | v4.0 Ultimate Edition - Advanced Features
    |--------------------------------------------------------------------------
    |
    | Advanced security features including honeytokens, policy engine,
    | WAF export, and threat intelligence integration.
    |
    */

    'advanced' => [

        'honeytokens' => [
            'enabled' => env('RUNTIME_GUARD_HONEYTOKENS', false),
            'types' => ['api_key', 'password', 'jwt', 'session', 'database'],
            'rotation_days' => 30,
            'alert_on_access' => true,
        ],

        'policies' => [
            'enabled' => env('RUNTIME_GUARD_POLICIES', true),
            'cache_decisions' => true,
            'cache_ttl' => 60,
            'audit_decisions' => true,
            'default_decision' => 'allow',
        ],

        'waf_export' => [
            'enabled' => env('RUNTIME_GUARD_WAF_EXPORT', false),
            'formats' => ['aws_waf', 'cloudflare', 'modsecurity', 'nginx'],
            'auto_sync' => false,
            'sync_interval' => 3600,
        ],

        'threat_intel' => [
            'enabled' => env('RUNTIME_GUARD_THREAT_INTEL', false),
            'feeds' => ['abuseipdb', 'spamhaus', 'emerging_threats'],
            'cache_ttl' => 3600,
            'api_keys' => [
                'abuseipdb' => env('ABUSEIPDB_API_KEY'),
                'virustotal' => env('VIRUSTOTAL_API_KEY'),
            ],
        ],

    ],

];
