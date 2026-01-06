# Laravel RuntimeGuard

[![Latest Version on Packagist](https://img.shields.io/packagist/v/mounir/laravel-runtime-guard.svg?style=flat-square)](https://packagist.org/packages/mounir/laravel-runtime-guard)
[![Total Downloads](https://img.shields.io/packagist/dt/mounir/laravel-runtime-guard.svg?style=flat-square)](https://packagist.org/packages/mounir/laravel-runtime-guard)
[![License](https://img.shields.io/packagist/l/mounir/laravel-runtime-guard.svg?style=flat-square)](https://packagist.org/packages/mounir/laravel-runtime-guard)

A comprehensive security-focused runtime monitoring and guard layer for Laravel applications.

## Overview

RuntimeGuard provides an extensible framework for runtime security inspection of your Laravel application. Unlike static analyzers that scan code, RuntimeGuard operates at runtime, inspecting actual data flowing through your application.

### Key Features

- 🛡️ **Multiple Guards**: SQL Injection, XSS, Command Injection, File Operation guards
- ⚡ **High Performance**: Tiered inspection, deduplication caching, request sampling
- 🔄 **Smart Execution**: Pipeline strategies (full, short-circuit, threshold)
- 📊 **Threat Correlation**: Track patterns across multiple requests
- 🎚️ **Progressive Enforcement**: Escalate from logging to blocking
- 🎯 **Route Profiles**: Different guard configurations per route
- 🚩 **Feature Flags**: Runtime toggling without deployment
- 🧪 **Testing Utilities**: Fake implementations and assertions
- 📝 **Multiple Reporters**: Log, Database, Async (Queue)

## Requirements

- PHP 8.1+
- Laravel 10.0+ / 11.0+

## Installation

```bash
composer require mounir/laravel-runtime-guard
```

Publish the configuration file:

```bash
php artisan vendor:publish --tag=runtime-guard-config
```

For database reporting, publish migrations:

```bash
php artisan vendor:publish --tag=runtime-guard-migrations
php artisan migrate
```

## Quick Start

### Basic Usage

```php
use Mounir\RuntimeGuard\Facades\RuntimeGuard;

// Inspect input with all enabled guards
$results = RuntimeGuard::inspect($userInput);

// Inspect with a specific guard
$result = RuntimeGuard::inspectWith('sql-injection', $userInput);

// Check if threat was detected
if ($result->failed()) {
    Log::warning('Threat detected', [
        'level' => $result->getThreatLevel()->value,
        'message' => $result->getMessage(),
    ]);
}
```

### Using the Middleware

Add the middleware to your routes:

```php
// routes/web.php
Route::middleware(['runtime-guard'])->group(function () {
    Route::post('/submit', [FormController::class, 'submit']);
});

// Or with a specific profile
Route::middleware(['runtime-guard:admin'])->group(function () {
    Route::resource('/admin/users', AdminUserController::class);
});
```

### Using the Trait in Controllers

```php
use Mounir\RuntimeGuard\Traits\InspectsInput;

class FormController extends Controller
{
    use InspectsInput;

    public function submit(Request $request)
    {
        // Inspect all request input
        $this->inspectRequest($request);

        // Or inspect specific fields
        $this->inspectRequestFields(['name', 'email', 'message']);

        // Or inspect custom data
        $this->inspectInput($customData);

        // Continue processing...
    }
}
```

### Using PHP Attributes

```php
use Mounir\RuntimeGuard\Attributes\GuardProfile;
use Mounir\RuntimeGuard\Attributes\SkipGuard;

class AdminController extends Controller
{
    #[GuardProfile('admin')]
    public function sensitiveAction()
    {
        // Uses 'admin' profile configuration
    }

    #[SkipGuard(['xss'])]
    public function richTextEditor()
    {
        // XSS guard is skipped for this action
    }
}
```

## Configuration

```php
// config/runtime-guard.php

return [
    // Master switch
    'enabled' => env('RUNTIME_GUARD_ENABLED', true),

    // Dry run mode (inspect but don't block)
    'dry_run' => env('RUNTIME_GUARD_DRY_RUN', false),

    // Response mode: 'block', 'log', or 'silent'
    'mode' => env('RUNTIME_GUARD_MODE', 'log'),

    // Pipeline configuration
    'pipeline' => [
        'strategy' => 'short_circuit', // 'full', 'short_circuit', 'threshold'
        'tiered' => true,              // Enable quick scan + deep inspection
    ],

    // Performance optimization
    'performance' => [
        'deduplication' => [
            'enabled' => true,
            'max_entries' => 1000,
            'ttl' => 60,
        ],
        'sampling' => [
            'enabled' => false,
            'rate' => 1.0,
        ],
    ],

    // Threat correlation
    'correlation' => [
        'enabled' => true,
        'window_seconds' => 300,
        'alert_threshold' => 5,
    ],

    // Progressive enforcement
    'progressive' => [
        'enabled' => true,
        'thresholds' => [
            'log' => 1,
            'alert' => 3,
            'block' => 5,
        ],
    ],

    // Guards configuration
    'guards' => [
        'sql-injection' => [
            'class' => \Mounir\RuntimeGuard\Guards\SqlInjectionGuard::class,
            'enabled' => true,
            'priority' => 100,
        ],
        'xss' => [
            'class' => \Mounir\RuntimeGuard\Guards\XssGuard::class,
            'enabled' => true,
            'priority' => 90,
        ],
        'command-injection' => [
            'class' => \Mounir\RuntimeGuard\Guards\CommandInjectionGuard::class,
            'enabled' => true,
            'priority' => 95,
        ],
        'file-operation' => [
            'class' => \Mounir\RuntimeGuard\Guards\FileOperationGuard::class,
            'enabled' => true,
            'priority' => 85,
        ],
    ],

    // Route profiles
    'profiles' => [
        'api' => [
            'guards' => ['sql-injection', 'command-injection'],
            'mode' => 'log',
        ],
        'admin' => [
            'guards' => '*',
            'mode' => 'block',
        ],
    ],

    // Reporters
    'reporters' => [
        'log' => ['enabled' => true],
        'database' => ['enabled' => false],
        'async' => ['enabled' => false],
    ],
];
```

## Available Guards

| Guard | Description | Status |
|-------|-------------|--------|
| `sql-injection` | Detects SQL injection patterns | ✅ Included |
| `xss` | Detects XSS/Cross-Site Scripting | ✅ Included |
| `command-injection` | Detects shell command injection | ✅ Included |
| `file-operation` | Detects path traversal and dangerous file ops | ✅ Included |

## Artisan Commands

```bash
# List all registered guards
php artisan runtime-guard:list

# Test a guard with sample input
php artisan runtime-guard:test sql-injection "1' OR '1'='1"

# Check system status
php artisan runtime-guard:status

# Toggle a guard at runtime
php artisan runtime-guard:toggle sql-injection --disable
php artisan runtime-guard:toggle sql-injection --enable
```

## Testing

RuntimeGuard provides testing utilities for your application tests:

```php
use Mounir\RuntimeGuard\Facades\RuntimeGuard;
use Mounir\RuntimeGuard\Testing\GuardAssertions;

class SecurityTest extends TestCase
{
    use GuardAssertions;

    public function test_form_submission_is_inspected(): void
    {
        $fake = RuntimeGuard::fake();

        $this->post('/submit', ['name' => 'Test']);

        $fake->assertInspected();
        $fake->assertNoThreatsDetected();
    }

    public function test_sql_injection_is_blocked(): void
    {
        $fake = RuntimeGuard::fake();
        $fake->shouldDetectThreat('sql-injection');

        $response = $this->post('/submit', [
            'id' => "1' OR '1'='1",
        ]);

        $fake->assertThreatDetected();
        $fake->assertGuardTriggered('sql-injection');
    }
}
```

## Creating Custom Guards

```php
use Mounir\RuntimeGuard\Guards\AbstractGuard;
use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;

class MyCustomGuard extends AbstractGuard
{
    // Quick scan patterns for fast detection
    protected array $quickPatterns = ['dangerous_pattern'];

    public function getName(): string
    {
        return 'my-custom';
    }

    protected function getPatterns(): array
    {
        return [
            'dangerous_pattern' => [
                'pattern1',
                'pattern2',
            ],
        ];
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        // Use compiled patterns for efficient matching
        if ($this->matchPattern('dangerous_pattern', $input)) {
            return $this->threat(
                'Dangerous pattern detected',
                ThreatLevel::HIGH,
                ['input_sample' => substr($input, 0, 100)]
            );
        }

        return $this->pass();
    }
}
```

Register your custom guard in the config:

```php
'guards' => [
    'my-custom' => [
        'class' => App\Guards\MyCustomGuard::class,
        'enabled' => true,
        'priority' => 80,
    ],
],
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Application                         │
│            (Controllers, Services, Jobs, etc.)              │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
          ┌─────────────────┐  ┌─────────────────┐
          │   Middleware    │  │     Facade      │
          │ RuntimeGuard    │  │  RuntimeGuard   │
          └─────────────────┘  └─────────────────┘
                    │                   │
                    └─────────┬─────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     GuardManager                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                    GuardPipeline                      │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    │  │
│  │  │SQL Guard│ │XSS Guard│ │Cmd Guard│ │File Grd │    │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘    │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌───────────────┐  │
│  │ Deduplication  │ │    Sampling    │ │ Input Limiter │  │
│  └────────────────┘ └────────────────┘ └───────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌───────────────┐  │
│  │  Correlation   │ │  Progressive   │ │   Profiles    │  │
│  │    Engine      │ │  Enforcement   │ │   Resolver    │  │
│  └────────────────┘ └────────────────┘ └───────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Reporters                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ LogReporter │ │ DbReporter  │ │AsyncReporter│           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

## Events

RuntimeGuard fires Laravel events you can listen to:

```php
// In your EventServiceProvider
protected $listen = [
    \Mounir\RuntimeGuard\Events\ThreatDetected::class => [
        \App\Listeners\NotifySecurityTeam::class,
    ],
    \Mounir\RuntimeGuard\Events\CorrelationThresholdExceeded::class => [
        \App\Listeners\BlockSuspiciousActor::class,
    ],
];
```

## Development

```bash
# Run tests
composer test

# Static analysis
composer analyse

# Code formatting
composer format
```

## Security

If you discover any security-related issues, please email security@example.com instead of using the issue tracker.

## Credits

- [Mounir](https://github.com/mounir)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.