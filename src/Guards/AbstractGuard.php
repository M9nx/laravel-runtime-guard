<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Guards;

use Mounir\RuntimeGuard\Contracts\BootableGuard;
use Mounir\RuntimeGuard\Contracts\ContextAwareGuard;
use Mounir\RuntimeGuard\Contracts\GuardInterface;
use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;
use Mounir\RuntimeGuard\Contracts\TieredGuard;
use Mounir\RuntimeGuard\Support\GuardResult;
use Mounir\RuntimeGuard\Support\InspectionContext;

/**
 * Base class for all guards providing common functionality.
 *
 * Extend this class to create new guards with minimal boilerplate.
 * Implements tiered inspection, context-awareness, and pattern caching.
 */
abstract class AbstractGuard implements GuardInterface, TieredGuard, ContextAwareGuard, BootableGuard
{
    protected bool $enabled = true;

    protected int $priority = 0;

    protected bool $booted = false;

    /**
     * Pre-compiled regex patterns for performance.
     *
     * @var array<string, string>
     */
    protected array $compiledPatterns = [];

    /**
     * Patterns for quick scan (lightweight checks).
     *
     * @var array<string>
     */
    protected array $quickPatterns = [];

    /**
     * Patterns for deep inspection (thorough checks).
     *
     * @var array<string>
     */
    protected array $deepPatterns = [];

    /**
     * Pattern compilation cache across instances.
     *
     * @var array<string, string>
     */
    protected static array $patternCache = [];

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        protected array $config = [],
    ) {
        $this->enabled = $this->config['enabled'] ?? true;
        $this->priority = $this->config['priority'] ?? 0;
    }

    /**
     * Boot the guard (compile patterns, initialize resources).
     */
    public function boot(): void
    {
        if ($this->booted) {
            return;
        }

        $this->compilePatterns();
        $this->onBoot();
        $this->booted = true;
    }

    /**
     * Check if the guard has been booted.
     */
    public function isBooted(): bool
    {
        return $this->booted;
    }

    /**
     * Hook for subclasses to perform additional boot logic.
     */
    protected function onBoot(): void
    {
        // Override in subclasses if needed
    }

    /**
     * Compile patterns for efficient matching.
     */
    protected function compilePatterns(): void
    {
        $patterns = $this->getPatterns();

        foreach ($patterns as $name => $pattern) {
            $cacheKey = static::class . ':' . $name;

            if (isset(self::$patternCache[$cacheKey])) {
                $this->compiledPatterns[$name] = self::$patternCache[$cacheKey];
                continue;
            }

            // Combine patterns into single regex for efficiency
            if (is_array($pattern)) {
                $combined = '/(?:' . implode('|', array_map(
                    fn ($p) => '(?:' . trim($p, '/') . ')',
                    $pattern
                )) . ')/i';
                $this->compiledPatterns[$name] = $combined;
            } else {
                $this->compiledPatterns[$name] = $pattern;
            }

            self::$patternCache[$cacheKey] = $this->compiledPatterns[$name];
        }
    }

    /**
     * Get patterns to compile.
     * Override in subclasses to return guard-specific patterns.
     *
     * @return array<string, string|array<string>>
     */
    protected function getPatterns(): array
    {
        return [];
    }

    /**
     * Perform the actual inspection logic.
     *
     * @param  mixed  $input
     * @param  array<string, mixed>  $context
     */
    abstract protected function performInspection(mixed $input, array $context = []): GuardResultInterface;

    public function inspect(mixed $input, array $context = []): GuardResultInterface
    {
        if (! $this->isEnabled()) {
            return GuardResult::pass($this->getName(), 'Guard is disabled');
        }

        if (! $this->booted) {
            $this->boot();
        }

        if (! $this->shouldInspect($input, $context)) {
            return GuardResult::pass($this->getName(), 'Inspection skipped');
        }

        return $this->performInspection($input, $context);
    }

    /**
     * {@inheritdoc}
     */
    public function inspectWithContext(mixed $input, InspectionContext $context): GuardResultInterface
    {
        if (! $this->isEnabled()) {
            return GuardResult::pass($this->getName(), 'Guard is disabled');
        }

        if (! $this->booted) {
            $this->boot();
        }

        if ($this->shouldSkipContext($context)) {
            return GuardResult::pass($this->getName(), 'Context excluded');
        }

        return $this->performInspection($input, $context->toArray());
    }

    /**
     * {@inheritdoc}
     */
    public function quickScan(mixed $input, InspectionContext $context): ?GuardResultInterface
    {
        if (! $this->booted) {
            $this->boot();
        }

        // Quick scan: use lightweight patterns only
        $normalized = $this->normalizeForScan($input);

        if ($normalized === '') {
            return null; // No obvious threat
        }

        foreach ($this->quickPatterns as $pattern) {
            if (isset($this->compiledPatterns[$pattern])) {
                if (preg_match($this->compiledPatterns[$pattern], $normalized)) {
                    return $this->createQuickScanResult($pattern, $normalized);
                }
            }
        }

        return null; // No quick threat found, may need deep inspection
    }

    /**
     * {@inheritdoc}
     */
    public function deepInspect(mixed $input, InspectionContext $context): GuardResultInterface
    {
        // Full inspection with all patterns and analysis
        return $this->performInspection($input, $context->toArray());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsQuickScan(): bool
    {
        return ! empty($this->quickPatterns);
    }

    /**
     * {@inheritdoc}
     */
    public function shouldSkipContext(InspectionContext $context): bool
    {
        // Default: check if this guard is excluded for the route
        $excludedGuards = $context->meta('excluded_guards', []);

        return in_array($this->getName(), $excludedGuards, true);
    }

    /**
     * Normalize input for quick scanning.
     */
    protected function normalizeForScan(mixed $input): string
    {
        if (is_string($input)) {
            return strtolower($input);
        }

        if (is_array($input)) {
            return strtolower(json_encode($input) ?: '');
        }

        return '';
    }

    /**
     * Create a result from quick scan match.
     */
    protected function createQuickScanResult(string $pattern, string $matched): GuardResultInterface
    {
        return GuardResult::threat(
            guard: $this->getName(),
            message: "Quick scan detected potential threat (pattern: {$pattern})",
            level: ThreatLevel::MEDIUM,
            details: [
                'scan_type' => 'quick',
                'pattern' => $pattern,
                'matched_sample' => substr($matched, 0, 100),
            ]
        );
    }

    /**
     * Determine if this guard should inspect the given input.
     *
     * Override this method to add pre-inspection filtering logic.
     *
     * @param  array<string, mixed>  $context
     */
    protected function shouldInspect(mixed $input, array $context = []): bool
    {
        return true;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getPriority(): int
    {
        return $this->priority;
    }

    /**
     * Get a config value with optional default.
     */
    protected function getConfig(string $key, mixed $default = null): mixed
    {
        return data_get($this->config, $key, $default);
    }

    /**
     * Create a passing result.
     */
    protected function pass(string $message = 'No threat detected'): GuardResult
    {
        return GuardResult::pass($this->getName(), $message);
    }

    /**
     * Create a threat result.
     */
    protected function threat(
        string $message,
        ThreatLevel $level = ThreatLevel::MEDIUM,
        array $details = []
    ): GuardResult {
        return GuardResult::threat($this->getName(), $message, $level, $details);
    }

    /**
     * Match against a compiled pattern.
     */
    protected function matchPattern(string $patternName, string $input): bool
    {
        if (! isset($this->compiledPatterns[$patternName])) {
            return false;
        }

        return (bool) preg_match($this->compiledPatterns[$patternName], $input);
    }

    /**
     * Get all matches for a compiled pattern.
     *
     * @return array<string>
     */
    protected function getPatternMatches(string $patternName, string $input): array
    {
        if (! isset($this->compiledPatterns[$patternName])) {
            return [];
        }

        preg_match_all($this->compiledPatterns[$patternName], $input, $matches);

        return $matches[0] ?? [];
    }

    /**
     * Clear pattern cache (useful for testing).
     */
    public static function clearPatternCache(): void
    {
        self::$patternCache = [];
    }
}
