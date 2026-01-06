# Contributing to Laravel RuntimeGuard

Thank you for considering contributing to RuntimeGuard! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Creating a New Guard](#creating-a-new-guard)
- [Creating a New Reporter](#creating-a-new-reporter)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a branch for your feature or fix

```bash
git checkout -b feature/my-new-guard
```

## Development Setup

```bash
# Install dependencies
composer install

# Run tests
composer test

# Run static analysis
composer analyse

# Format code
composer format
```

## Creating a New Guard

Guards are the core extension point of RuntimeGuard. Follow these steps to create a new guard:

### Step 1: Create the Guard Class

Create a new file in `src/Guards/`:

```php
<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Guards;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;
use Mounir\RuntimeGuard\Support\GuardResult;

/**
 * Detects [description of what this guard detects].
 */
class MyNewGuard extends AbstractGuard
{
    public function getName(): string
    {
        return 'my-new-guard'; // kebab-case, unique identifier
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        // 1. Normalize/validate input
        if (!is_string($input)) {
            return $this->pass('Non-string input skipped');
        }

        // 2. Perform detection logic
        if ($this->detectThreat($input)) {
            return GuardResult::fail(
                guardName: $this->getName(),
                threatLevel: ThreatLevel::HIGH,
                message: 'Threat description',
                metadata: [
                    'additional' => 'context',
                ],
            );
        }

        // 3. Return pass if no threat
        return $this->pass();
    }

    private function detectThreat(string $input): bool
    {
        // Your detection logic
        return false;
    }
}
```

### Step 2: Register in Configuration

Add your guard to `config/runtime-guard.php`:

```php
'guards' => [
    'my-new-guard' => [
        'class' => \Mounir\RuntimeGuard\Guards\MyNewGuard::class,
        'enabled' => true,
        'priority' => 50,
        // Guard-specific options...
    ],
],
```

### Step 3: Write Tests

Create tests in `tests/Unit/Guards/MyNewGuardTest.php`:

```php
<?php

use Mounir\RuntimeGuard\Guards\MyNewGuard;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;

test('detects [specific threat]', function () {
    $guard = new MyNewGuard(['enabled' => true]);
    $result = $guard->inspect('malicious input');

    expect($result->failed())->toBeTrue();
    expect($result->getThreatLevel())->toBe(ThreatLevel::HIGH);
});

test('passes clean input', function () {
    $guard = new MyNewGuard(['enabled' => true]);
    $result = $guard->inspect('clean input');

    expect($result->passed())->toBeTrue();
});
```

### Guard Implementation Guidelines

1. **Single Responsibility**: Each guard should focus on one type of threat
2. **Configurability**: Accept configuration in constructor, use `$this->getConfig()`
3. **Input Tolerance**: Handle various input types gracefully
4. **Meaningful Messages**: Return clear, actionable messages
5. **Appropriate Threat Levels**: Use consistent threat level assignment
6. **Metadata**: Include relevant metadata for debugging/logging

### Threat Level Guidelines

| Level | Use When |
|-------|----------|
| `NONE` | No threat detected |
| `LOW` | Suspicious but likely false positive |
| `MEDIUM` | Potential threat requiring review |
| `HIGH` | Likely threat, should be blocked |
| `CRITICAL` | Confirmed attack pattern |

## Creating a New Reporter

Reporters handle what happens after a threat is detected.

### Step 1: Create the Reporter Class

```php
<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Reporters;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ReporterInterface;

class MyReporter implements ReporterInterface
{
    public function __construct(
        protected array $config = [],
    ) {}

    public function report(GuardResultInterface $result, array $context = []): void
    {
        // Send alert, store in database, etc.
    }

    public function shouldReport(GuardResultInterface $result): bool
    {
        return $result->failed();
    }
}
```

### Step 2: Register the Reporter

Add to `config/runtime-guard.php`:

```php
'reporters' => [
    'my-reporter' => [
        'class' => \Mounir\RuntimeGuard\Reporters\MyReporter::class,
        'enabled' => true,
        // Reporter-specific config...
    ],
],
```

## Testing Guidelines

- Write tests for both success and failure cases
- Test edge cases (null, empty string, arrays, objects)
- Test configuration options
- Use descriptive test names
- Follow Pest PHP conventions

```bash
# Run all tests
composer test

# Run specific test file
./vendor/bin/pest tests/Unit/Guards/MyNewGuardTest.php

# Run with coverage
./vendor/bin/pest --coverage
```

## Pull Request Process

1. Ensure all tests pass
2. Run static analysis: `composer analyse`
3. Format code: `composer format`
4. Update documentation if needed
5. Create detailed PR description
6. Link related issues

## Coding Standards

- Follow PSR-12
- Use strict types: `declare(strict_types=1);`
- Type hint everything (parameters, returns, properties)
- Use `readonly` where appropriate
- Use `final` for classes not designed for extension
- Write descriptive docblocks
- Use meaningful variable names

### Naming Conventions

| Element | Convention | Example |
|---------|------------|---------|
| Guard names | kebab-case | `sql-injection`, `xss-protection` |
| Class names | PascalCase | `SqlInjectionGuard` |
| Methods | camelCase | `performInspection()` |
| Config keys | snake_case | `block_threshold` |
| Constants | UPPER_SNAKE | `MAX_DEPTH` |

## Questions?

Open an issue with the `question` label.
