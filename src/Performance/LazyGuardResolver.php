<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Performance;

use M9nx\RuntimeGuard\Contracts\GuardInterface;
use Illuminate\Contracts\Container\Container;

/**
 * Lazy Guard Resolver.
 *
 * Defers guard instantiation until first use for faster boot time.
 */
class LazyGuardResolver
{
    protected Container $container;
    protected array $guardClasses = [];
    protected array $resolvedGuards = [];
    protected array $resolutionTimes = [];
    protected array $guardPriorities = [];

    public function __construct(Container $container)
    {
        $this->container = $container;
    }

    /**
     * Register a guard class for lazy resolution.
     */
    public function register(string $name, string $class, int $priority = 0): self
    {
        $this->guardClasses[$name] = $class;
        $this->guardPriorities[$name] = $priority;

        return $this;
    }

    /**
     * Register multiple guards.
     */
    public function registerMany(array $guards): self
    {
        foreach ($guards as $name => $config) {
            if (is_string($config)) {
                $this->register($name, $config);
            } else {
                $this->register(
                    $name,
                    $config['class'],
                    $config['priority'] ?? 0
                );
            }
        }

        return $this;
    }

    /**
     * Resolve a guard by name.
     */
    public function resolve(string $name): ?GuardInterface
    {
        // Return cached instance
        if (isset($this->resolvedGuards[$name])) {
            return $this->resolvedGuards[$name];
        }

        // Check if registered
        if (!isset($this->guardClasses[$name])) {
            return null;
        }

        $start = hrtime(true);

        // Resolve from container
        $guard = $this->container->make($this->guardClasses[$name]);

        // Boot the guard
        if (method_exists($guard, 'onBoot')) {
            $guard->onBoot();
        }

        $this->resolutionTimes[$name] = (hrtime(true) - $start) / 1_000_000; // ms
        $this->resolvedGuards[$name] = $guard;

        return $guard;
    }

    /**
     * Resolve all registered guards.
     */
    public function resolveAll(): array
    {
        foreach (array_keys($this->guardClasses) as $name) {
            $this->resolve($name);
        }

        return $this->resolvedGuards;
    }

    /**
     * Resolve guards in priority order.
     */
    public function resolveByPriority(): array
    {
        // Sort by priority (higher first)
        arsort($this->guardPriorities);

        $sorted = [];
        foreach (array_keys($this->guardPriorities) as $name) {
            $guard = $this->resolve($name);
            if ($guard) {
                $sorted[$name] = $guard;
            }
        }

        return $sorted;
    }

    /**
     * Check if a guard is registered.
     */
    public function has(string $name): bool
    {
        return isset($this->guardClasses[$name]);
    }

    /**
     * Check if a guard is resolved.
     */
    public function isResolved(string $name): bool
    {
        return isset($this->resolvedGuards[$name]);
    }

    /**
     * Get all registered guard names.
     */
    public function getRegistered(): array
    {
        return array_keys($this->guardClasses);
    }

    /**
     * Get all resolved guard names.
     */
    public function getResolved(): array
    {
        return array_keys($this->resolvedGuards);
    }

    /**
     * Get unresolved guard names.
     */
    public function getUnresolved(): array
    {
        return array_diff(
            array_keys($this->guardClasses),
            array_keys($this->resolvedGuards)
        );
    }

    /**
     * Get resolution times.
     */
    public function getResolutionTimes(): array
    {
        return $this->resolutionTimes;
    }

    /**
     * Get statistics.
     */
    public function getStatistics(): array
    {
        return [
            'registered' => count($this->guardClasses),
            'resolved' => count($this->resolvedGuards),
            'unresolved' => count($this->getUnresolved()),
            'total_resolution_time_ms' => array_sum($this->resolutionTimes),
            'avg_resolution_time_ms' => count($this->resolutionTimes) > 0
                ? array_sum($this->resolutionTimes) / count($this->resolutionTimes)
                : 0,
            'slowest_guards' => $this->getSlowestGuards(5),
        ];
    }

    /**
     * Get slowest guards by resolution time.
     */
    public function getSlowestGuards(int $limit = 5): array
    {
        arsort($this->resolutionTimes);

        return array_slice($this->resolutionTimes, 0, $limit, true);
    }

    /**
     * Pre-warm specific guards.
     */
    public function preWarm(array $names): void
    {
        foreach ($names as $name) {
            $this->resolve($name);
        }
    }

    /**
     * Clear resolved guards (useful for testing).
     */
    public function clear(): void
    {
        $this->resolvedGuards = [];
        $this->resolutionTimes = [];
    }

    /**
     * Create a proxy that resolves on first method call.
     */
    public function proxy(string $name): LazyGuardProxy
    {
        return new LazyGuardProxy($this, $name);
    }
}

/**
 * Proxy class for lazy guard resolution.
 */
class LazyGuardProxy implements GuardInterface
{
    protected LazyGuardResolver $resolver;
    protected string $name;
    protected ?GuardInterface $guard = null;

    public function __construct(LazyGuardResolver $resolver, string $name)
    {
        $this->resolver = $resolver;
        $this->name = $name;
    }

    protected function getGuard(): GuardInterface
    {
        if ($this->guard === null) {
            $this->guard = $this->resolver->resolve($this->name);
        }

        return $this->guard;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function inspect(mixed $input, array $context = []): \M9nx\RuntimeGuard\Contracts\GuardResultInterface
    {
        return $this->getGuard()->inspect($input, $context);
    }

    public function isEnabled(): bool
    {
        return $this->getGuard()->isEnabled();
    }

    public function getConfig(): array
    {
        return $this->getGuard()->getConfig();
    }

    public function onBoot(): void
    {
        $this->getGuard()->onBoot();
    }
}
