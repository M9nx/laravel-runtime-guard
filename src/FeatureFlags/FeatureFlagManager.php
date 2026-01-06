<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\FeatureFlags;

use Illuminate\Contracts\Cache\Repository as CacheRepository;

/**
 * Runtime feature flag management for guards.
 *
 * Allows toggling guards without deployment.
 */
class FeatureFlagManager
{
    private const PREFIX = 'runtime_guard:flag:';

    /**
     * In-memory flag overrides.
     *
     * @var array<string, bool>
     */
    private array $memoryFlags = [];

    public function __construct(
        private readonly string $driver = 'config',
        private readonly ?CacheRepository $cache = null,
        private readonly int $ttl = 300,
    ) {}

    /**
     * Create from configuration.
     */
    public static function fromConfig(array $config, ?CacheRepository $cache = null): self
    {
        return new self(
            driver: $config['driver'] ?? 'config',
            cache: $cache,
            ttl: $config['ttl'] ?? 300,
        );
    }

    /**
     * Check if a guard is enabled.
     */
    public function isEnabled(string $guardName, bool $default = true): bool
    {
        // Memory overrides take precedence
        if (isset($this->memoryFlags[$guardName])) {
            return $this->memoryFlags[$guardName];
        }

        // Check cache driver
        if ($this->driver === 'cache' && $this->cache) {
            $value = $this->cache->get(self::PREFIX . $guardName);

            if ($value !== null) {
                return (bool) $value;
            }
        }

        return $default;
    }

    /**
     * Enable a guard at runtime.
     */
    public function enable(string $guardName): void
    {
        $this->setFlag($guardName, true);
    }

    /**
     * Disable a guard at runtime.
     */
    public function disable(string $guardName): void
    {
        $this->setFlag($guardName, false);
    }

    /**
     * Set a flag value.
     */
    public function setFlag(string $guardName, bool $enabled): void
    {
        $this->memoryFlags[$guardName] = $enabled;

        if ($this->driver === 'cache' && $this->cache) {
            $this->cache->put(self::PREFIX . $guardName, $enabled, $this->ttl);
        }
    }

    /**
     * Remove a flag (revert to config default).
     */
    public function removeFlag(string $guardName): void
    {
        unset($this->memoryFlags[$guardName]);

        if ($this->driver === 'cache' && $this->cache) {
            $this->cache->forget(self::PREFIX . $guardName);
        }
    }

    /**
     * Get all active flag overrides.
     *
     * @return array<string, bool>
     */
    public function getActiveFlags(): array
    {
        return $this->memoryFlags;
    }

    /**
     * Clear all flag overrides.
     */
    public function clearAll(): void
    {
        // Clear cache flags
        if ($this->driver === 'cache' && $this->cache) {
            foreach (array_keys($this->memoryFlags) as $guardName) {
                $this->cache->forget(self::PREFIX . $guardName);
            }
        }

        $this->memoryFlags = [];
    }

    /**
     * Temporarily override a flag for a callback.
     *
     * @template T
     *
     * @param  callable(): T  $callback
     * @return T
     */
    public function withFlag(string $guardName, bool $enabled, callable $callback): mixed
    {
        $previous = $this->memoryFlags[$guardName] ?? null;

        $this->memoryFlags[$guardName] = $enabled;

        try {
            return $callback();
        } finally {
            if ($previous === null) {
                unset($this->memoryFlags[$guardName]);
            } else {
                $this->memoryFlags[$guardName] = $previous;
            }
        }
    }
}
