# Architecture Documentation

This document explains the internal architecture of Laravel RuntimeGuard.

## Directory Structure

```
laravel-runtime-guard/
├── config/
│   └── runtime-guard.php      # Package configuration
├── src/
│   ├── Contracts/             # Interfaces and abstract contracts
│   │   ├── GuardInterface.php
│   │   ├── GuardResultInterface.php
│   │   ├── GuardManagerInterface.php
│   │   ├── ReporterInterface.php
│   │   └── ThreatLevel.php
│   ├── Exceptions/            # Package exceptions
│   │   ├── RuntimeGuardException.php
│   │   ├── GuardNotFoundException.php
│   │   └── ThreatDetectedException.php
│   ├── Facades/               # Laravel facades
│   │   └── RuntimeGuard.php
│   ├── Guards/                # Guard implementations
│   │   ├── AbstractGuard.php
│   │   └── SqlInjectionGuard.php
│   ├── Reporters/             # Reporter implementations
│   │   └── LogReporter.php
│   ├── Support/               # Support classes and helpers
│   │   └── GuardResult.php
│   ├── GuardManager.php       # Central orchestrator
│   └── RuntimeGuardServiceProvider.php
├── tests/
│   ├── Feature/               # Integration tests
│   ├── Unit/                  # Unit tests
│   └── TestCase.php           # Base test case
├── docs/                      # Documentation
│   └── ARCHITECTURE.md
├── composer.json
├── phpunit.xml
├── phpstan.neon
├── LICENSE
├── README.md
└── CONTRIBUTING.md
```

## Core Components

### 1. Contracts (Interfaces)

The `Contracts/` directory contains all interfaces that define the public API:

#### `GuardInterface`

The core contract that all guards must implement:

```php
interface GuardInterface
{
    public function getName(): string;
    public function inspect(mixed $input, array $context = []): GuardResultInterface;
    public function isEnabled(): bool;
    public function getPriority(): int;
}
```

- **getName()**: Returns unique identifier (kebab-case)
- **inspect()**: Main inspection method
- **isEnabled()**: Runtime enable/disable check
- **getPriority()**: Execution order (higher = first)

#### `GuardResultInterface`

Immutable result object returned by guards:

```php
interface GuardResultInterface
{
    public function passed(): bool;
    public function failed(): bool;
    public function getThreatLevel(): ThreatLevel;
    public function getMessage(): string;
    public function getMetadata(): array;
    public function getGuardName(): string;
}
```

#### `ThreatLevel` (Enum)

Severity classification:

```php
enum ThreatLevel: string
{
    case NONE = 'none';
    case LOW = 'low';
    case MEDIUM = 'medium';
    case HIGH = 'high';
    case CRITICAL = 'critical';
}
```

#### `GuardManagerInterface`

Central registry and orchestrator:

```php
interface GuardManagerInterface
{
    public function register(GuardInterface $guard): static;
    public function registerClass(string $guardClass): static;
    public function get(string $name): ?GuardInterface;
    public function has(string $name): bool;
    public function all(): array;
    public function enabled(): array;
    public function inspect(mixed $input, array $context = []): array;
    public function inspectWith(string $guardName, mixed $input, array $context = []): GuardResultInterface;
}
```

#### `ReporterInterface`

Handles post-detection actions:

```php
interface ReporterInterface
{
    public function report(GuardResultInterface $result, array $context = []): void;
    public function shouldReport(GuardResultInterface $result): bool;
}
```

### 2. Guard System

#### `AbstractGuard`

Base class providing common functionality:

```php
abstract class AbstractGuard implements GuardInterface
{
    // Template method pattern
    public function inspect(mixed $input, array $context = []): GuardResultInterface
    {
        if (! $this->isEnabled()) {
            return GuardResult::pass($this->getName(), 'Guard is disabled');
        }

        if (! $this->shouldInspect($input, $context)) {
            return GuardResult::pass($this->getName(), 'Inspection skipped');
        }

        return $this->performInspection($input, $context);
    }

    // Hook for subclasses
    abstract protected function performInspection(mixed $input, array $context = []): GuardResultInterface;
    
    // Optional override point
    protected function shouldInspect(mixed $input, array $context = []): bool
    {
        return true;
    }
}
```

**Key Features**:
- Template Method pattern for consistent flow
- Configuration injection via constructor
- Helper methods (`pass()`, `getConfig()`)
- `shouldInspect()` hook for pre-filtering

### 3. GuardManager

The central orchestrator:

```php
class GuardManager implements GuardManagerInterface
{
    protected array $guards = [];          // Resolved instances
    protected array $guardClasses = [];    // Lazy-load queue

    public function inspect(mixed $input, array $context = []): array
    {
        $results = [];
        foreach ($this->enabled() as $guard) {
            $results[] = $guard->inspect($input, $context);
        }
        return $results;
    }
}
```

**Features**:
- Lazy loading via `registerClass()`
- Priority-based execution order
- Container-based resolution for DI

### 4. Service Provider

```php
class RuntimeGuardServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // 1. Merge config
        // 2. Register GuardManager singleton
        // 3. Register reporters
    }

    public function boot(): void
    {
        // 1. Publish config
        // 2. Register guards from config
    }
}
```

**Registration Flow**:
1. Config is merged with defaults
2. GuardManager bound as singleton
3. Guards registered during boot (allows config overrides)
4. Guards resolved lazily on first use

## Data Flow

```
User Input
    │
    ▼
┌─────────────────────┐
│   RuntimeGuard      │  ← Facade
│   (GuardManager)    │
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│  enabled()          │  ← Get enabled guards, sorted by priority
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│  Guard::inspect()   │  ← Each guard inspects input
│  ├─ isEnabled?      │
│  ├─ shouldInspect?  │
│  └─ performInspect  │
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│  GuardResult        │  ← Immutable result object
│  ├─ passed/failed   │
│  ├─ threatLevel     │
│  ├─ message         │
│  └─ metadata        │
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│  Reporter           │  ← Handle result (log, alert, etc.)
└─────────────────────┘
```

## Extension Points

### 1. Custom Guards

Extend `AbstractGuard` and implement `getName()` + `performInspection()`.

### 2. Custom Reporters

Implement `ReporterInterface`.

### 3. Custom Result Types

Implement `GuardResultInterface` (rarely needed).

### 4. Configuration

All guards/reporters accept configuration arrays for customization.

## Design Decisions

### Why Interfaces?

- Enable mocking in tests
- Allow custom implementations
- Clear API boundaries
- IDE autocompletion

### Why Lazy Loading?

Guards may have heavy dependencies. Lazy loading ensures only used guards are instantiated.

### Why Priority System?

Some guards should run before others (e.g., quick checks before expensive ones).

### Why Immutable Results?

- Thread safety
- Prevents accidental modification
- Clear data contracts

### Why Separate Reporters?

- Separation of concerns
- Guards focus on detection
- Reporters handle notification
- Easy to add new reporting channels

## Future Considerations

### Planned Extensions

1. **Middleware**: Auto-inspect HTTP requests
2. **Events**: Fire Laravel events on detection
3. **Caching**: Cache inspection results
4. **Rate Limiting**: Prevent inspection abuse
5. **Async Reporting**: Queue reporter execution

### Breaking Change Prevention

- All interfaces are versioned
- New methods added as optional (with defaults)
- Config changes are additive
- Deprecation notices before removal
