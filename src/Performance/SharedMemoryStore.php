<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Performance;

use Illuminate\Support\Facades\Cache;

/**
 * Shared Memory Store for Laravel Octane.
 *
 * Provides fast inter-worker state sharing using Swoole tables or APCu.
 */
class SharedMemoryStore
{
    protected string $driver;
    protected ?object $swooleTable = null;
    protected string $prefix = 'rtg:';
    protected int $defaultTtl = 3600;

    public function __construct(?string $driver = null)
    {
        $this->driver = $driver ?? $this->detectDriver();
        $this->initialize();
    }

    /**
     * Detect available shared memory driver.
     */
    protected function detectDriver(): string
    {
        // Check for Swoole table (Laravel Octane with Swoole)
        if (extension_loaded('swoole') && class_exists(\Swoole\Table::class)) {
            return 'swoole';
        }

        // Check for APCu
        if (extension_loaded('apcu') && apcu_enabled()) {
            return 'apcu';
        }

        // Fallback to array (per-process only)
        return 'array';
    }

    /**
     * Initialize the store.
     */
    protected function initialize(): void
    {
        if ($this->driver === 'swoole') {
            $this->initializeSwooleTable();
        }
    }

    /**
     * Initialize Swoole table.
     */
    protected function initializeSwooleTable(): void
    {
        if (!class_exists(\Swoole\Table::class)) {
            $this->driver = 'array';
            return;
        }

        // Create table for pattern cache
        $this->swooleTable = new \Swoole\Table(8192);
        $this->swooleTable->column('value', \Swoole\Table::TYPE_STRING, 4096);
        $this->swooleTable->column('expires', \Swoole\Table::TYPE_INT);
        $this->swooleTable->create();
    }

    /**
     * Get the current driver.
     */
    public function getDriver(): string
    {
        return $this->driver;
    }

    /**
     * Set a value.
     */
    public function set(string $key, mixed $value, ?int $ttl = null): bool
    {
        $key = $this->prefix . $key;
        $ttl = $ttl ?? $this->defaultTtl;
        $expires = time() + $ttl;

        return match ($this->driver) {
            'swoole' => $this->swooleSet($key, $value, $expires),
            'apcu' => apcu_store($key, $value, $ttl),
            default => $this->arraySet($key, $value, $expires),
        };
    }

    /**
     * Get a value.
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $key = $this->prefix . $key;

        return match ($this->driver) {
            'swoole' => $this->swooleGet($key, $default),
            'apcu' => $this->apcuGet($key, $default),
            default => $this->arrayGet($key, $default),
        };
    }

    /**
     * Check if key exists.
     */
    public function has(string $key): bool
    {
        $key = $this->prefix . $key;

        return match ($this->driver) {
            'swoole' => $this->swooleTable?->exists($key) ?? false,
            'apcu' => apcu_exists($key),
            default => isset($GLOBALS['__rtg_shared'][$key]),
        };
    }

    /**
     * Delete a key.
     */
    public function forget(string $key): bool
    {
        $key = $this->prefix . $key;

        return match ($this->driver) {
            'swoole' => $this->swooleTable?->del($key) ?? false,
            'apcu' => apcu_delete($key),
            default => $this->arrayForget($key),
        };
    }

    /**
     * Increment a value atomically.
     */
    public function increment(string $key, int $amount = 1): int
    {
        $key = $this->prefix . $key;

        return match ($this->driver) {
            'swoole' => $this->swooleIncrement($key, $amount),
            'apcu' => apcu_inc($key, $amount) ?: 0,
            default => $this->arrayIncrement($key, $amount),
        };
    }

    /**
     * Decrement a value atomically.
     */
    public function decrement(string $key, int $amount = 1): int
    {
        return $this->increment($key, -$amount);
    }

    /**
     * Get or set a value.
     */
    public function remember(string $key, int $ttl, callable $callback): mixed
    {
        $value = $this->get($key);

        if ($value !== null) {
            return $value;
        }

        $value = $callback();
        $this->set($key, $value, $ttl);

        return $value;
    }

    /**
     * Clear all keys with prefix.
     */
    public function flush(): bool
    {
        return match ($this->driver) {
            'swoole' => $this->swooleFlush(),
            'apcu' => $this->apcuFlush(),
            default => $this->arrayFlush(),
        };
    }

    /**
     * Get statistics.
     */
    public function getStatistics(): array
    {
        return match ($this->driver) {
            'swoole' => $this->swooleStats(),
            'apcu' => $this->apcuStats(),
            default => $this->arrayStats(),
        };
    }

    // Swoole implementations

    protected function swooleSet(string $key, mixed $value, int $expires): bool
    {
        if (!$this->swooleTable) {
            return false;
        }

        return $this->swooleTable->set($key, [
            'value' => serialize($value),
            'expires' => $expires,
        ]);
    }

    protected function swooleGet(string $key, mixed $default): mixed
    {
        if (!$this->swooleTable) {
            return $default;
        }

        $row = $this->swooleTable->get($key);
        if (!$row) {
            return $default;
        }

        if ($row['expires'] < time()) {
            $this->swooleTable->del($key);
            return $default;
        }

        return unserialize($row['value']);
    }

    protected function swooleIncrement(string $key, int $amount): int
    {
        $current = $this->swooleGet($key, 0);
        $new = (int) $current + $amount;
        $this->swooleSet($key, $new, time() + $this->defaultTtl);

        return $new;
    }

    protected function swooleFlush(): bool
    {
        if (!$this->swooleTable) {
            return false;
        }

        foreach ($this->swooleTable as $key => $row) {
            if (str_starts_with($key, $this->prefix)) {
                $this->swooleTable->del($key);
            }
        }

        return true;
    }

    protected function swooleStats(): array
    {
        if (!$this->swooleTable) {
            return ['driver' => 'swoole', 'available' => false];
        }

        return [
            'driver' => 'swoole',
            'available' => true,
            'count' => $this->swooleTable->count(),
            'memory_size' => $this->swooleTable->getMemorySize(),
        ];
    }

    // APCu implementations

    protected function apcuGet(string $key, mixed $default): mixed
    {
        $success = false;
        $value = apcu_fetch($key, $success);

        return $success ? $value : $default;
    }

    protected function apcuFlush(): bool
    {
        $iterator = new \APCUIterator('/^' . preg_quote($this->prefix, '/') . '/');
        return apcu_delete($iterator);
    }

    protected function apcuStats(): array
    {
        $info = apcu_cache_info(true);

        return [
            'driver' => 'apcu',
            'available' => true,
            'num_slots' => $info['num_slots'] ?? 0,
            'num_hits' => $info['num_hits'] ?? 0,
            'num_misses' => $info['num_misses'] ?? 0,
            'num_entries' => $info['num_entries'] ?? 0,
            'mem_size' => $info['mem_size'] ?? 0,
        ];
    }

    // Array (fallback) implementations

    protected array $arrayStore = [];

    protected function arraySet(string $key, mixed $value, int $expires): bool
    {
        $GLOBALS['__rtg_shared'][$key] = [
            'value' => $value,
            'expires' => $expires,
        ];

        return true;
    }

    protected function arrayGet(string $key, mixed $default): mixed
    {
        if (!isset($GLOBALS['__rtg_shared'][$key])) {
            return $default;
        }

        $item = $GLOBALS['__rtg_shared'][$key];
        if ($item['expires'] < time()) {
            unset($GLOBALS['__rtg_shared'][$key]);
            return $default;
        }

        return $item['value'];
    }

    protected function arrayForget(string $key): bool
    {
        unset($GLOBALS['__rtg_shared'][$key]);

        return true;
    }

    protected function arrayIncrement(string $key, int $amount): int
    {
        $current = $this->arrayGet($key, 0);
        $new = (int) $current + $amount;
        $this->arraySet($key, $new, time() + $this->defaultTtl);

        return $new;
    }

    protected function arrayFlush(): bool
    {
        foreach (array_keys($GLOBALS['__rtg_shared'] ?? []) as $key) {
            if (str_starts_with($key, $this->prefix)) {
                unset($GLOBALS['__rtg_shared'][$key]);
            }
        }

        return true;
    }

    protected function arrayStats(): array
    {
        $count = 0;
        foreach (array_keys($GLOBALS['__rtg_shared'] ?? []) as $key) {
            if (str_starts_with($key, $this->prefix)) {
                $count++;
            }
        }

        return [
            'driver' => 'array',
            'available' => true,
            'count' => $count,
            'note' => 'Array driver is per-process only, not shared across workers',
        ];
    }
}
