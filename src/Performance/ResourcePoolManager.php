<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Performance;

use Illuminate\Support\Facades\Cache;
use RuntimeException;

/**
 * Resource Pool Manager.
 *
 * Manages pooled resources for efficient guard execution:
 * - Connection pooling
 * - Object recycling
 * - Memory management
 * - Resource limits
 */
class ResourcePoolManager
{
    private array $config;
    private array $pools = [];
    private array $statistics = [];
    private string $cachePrefix;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->cachePrefix = $config['cache_prefix'] ?? 'resource_pool:';

        $this->initializePools($config['pools'] ?? []);
    }

    /**
     * Initialize resource pools.
     */
    private function initializePools(array $poolConfigs): void
    {
        $defaults = [
            'pattern_cache' => [
                'type' => 'memory',
                'max_size' => 100,
                'ttl' => 3600,
            ],
            'compiled_regex' => [
                'type' => 'memory',
                'max_size' => 50,
                'ttl' => null,
            ],
            'connection' => [
                'type' => 'connection',
                'max_size' => 10,
                'idle_timeout' => 60,
            ],
            'buffer' => [
                'type' => 'buffer',
                'max_size' => 20,
                'buffer_size' => 65536,
            ],
        ];

        $poolConfigs = array_merge($defaults, $poolConfigs);

        foreach ($poolConfigs as $name => $config) {
            $this->pools[$name] = new ResourcePool($name, $config);
            $this->statistics[$name] = [
                'hits' => 0,
                'misses' => 0,
                'allocations' => 0,
                'releases' => 0,
                'evictions' => 0,
            ];
        }
    }

    /**
     * Acquire a resource from pool.
     */
    public function acquire(string $poolName, ?string $key = null): mixed
    {
        if (!isset($this->pools[$poolName])) {
            throw new RuntimeException("Pool not found: {$poolName}");
        }

        $pool = $this->pools[$poolName];

        if ($key !== null) {
            $resource = $pool->get($key);
            if ($resource !== null) {
                $this->statistics[$poolName]['hits']++;
                return $resource;
            }
            $this->statistics[$poolName]['misses']++;
        }

        $resource = $pool->acquire();
        $this->statistics[$poolName]['allocations']++;

        return $resource;
    }

    /**
     * Release a resource back to pool.
     */
    public function release(string $poolName, mixed $resource, ?string $key = null): void
    {
        if (!isset($this->pools[$poolName])) {
            return;
        }

        $pool = $this->pools[$poolName];
        $pool->release($resource, $key);
        $this->statistics[$poolName]['releases']++;
    }

    /**
     * Store a value in pool with key.
     */
    public function store(string $poolName, string $key, mixed $value): void
    {
        if (!isset($this->pools[$poolName])) {
            throw new RuntimeException("Pool not found: {$poolName}");
        }

        $pool = $this->pools[$poolName];
        $evicted = $pool->store($key, $value);

        if ($evicted) {
            $this->statistics[$poolName]['evictions']++;
        }
    }

    /**
     * Get a value from pool by key.
     */
    public function get(string $poolName, string $key): mixed
    {
        if (!isset($this->pools[$poolName])) {
            return null;
        }

        $pool = $this->pools[$poolName];
        $value = $pool->get($key);

        if ($value !== null) {
            $this->statistics[$poolName]['hits']++;
        } else {
            $this->statistics[$poolName]['misses']++;
        }

        return $value;
    }

    /**
     * Execute with pooled resource.
     */
    public function withResource(string $poolName, callable $callback, ?string $key = null): mixed
    {
        $resource = $this->acquire($poolName, $key);

        try {
            $result = $callback($resource);
            $this->release($poolName, $resource, $key);
            return $result;
        } catch (\Throwable $e) {
            // Don't return bad resources to pool
            throw $e;
        }
    }

    /**
     * Get or create cached pattern.
     */
    public function getCompiledPattern(string $pattern): CompiledPattern
    {
        $key = md5($pattern);
        $cached = $this->get('compiled_regex', $key);

        if ($cached !== null) {
            return $cached;
        }

        $compiled = new CompiledPattern($pattern);
        $this->store('compiled_regex', $key, $compiled);

        return $compiled;
    }

    /**
     * Get buffer from pool.
     */
    public function getBuffer(): Buffer
    {
        return $this->acquire('buffer');
    }

    /**
     * Return buffer to pool.
     */
    public function returnBuffer(Buffer $buffer): void
    {
        $buffer->reset();
        $this->release('buffer', $buffer);
    }

    /**
     * Get pool statistics.
     */
    public function getStatistics(?string $poolName = null): array
    {
        if ($poolName !== null) {
            return array_merge(
                $this->statistics[$poolName] ?? [],
                ['pool_size' => $this->pools[$poolName]?->getSize() ?? 0]
            );
        }

        $stats = [];
        foreach ($this->pools as $name => $pool) {
            $stats[$name] = array_merge(
                $this->statistics[$name],
                [
                    'pool_size' => $pool->getSize(),
                    'hit_rate' => $this->calculateHitRate($name),
                ]
            );
        }

        return $stats;
    }

    /**
     * Calculate hit rate for a pool.
     */
    private function calculateHitRate(string $poolName): float
    {
        $hits = $this->statistics[$poolName]['hits'] ?? 0;
        $misses = $this->statistics[$poolName]['misses'] ?? 0;
        $total = $hits + $misses;

        return $total > 0 ? round($hits / $total, 4) : 0;
    }

    /**
     * Clear a specific pool.
     */
    public function clearPool(string $poolName): void
    {
        if (isset($this->pools[$poolName])) {
            $this->pools[$poolName]->clear();
            $this->statistics[$poolName] = [
                'hits' => 0,
                'misses' => 0,
                'allocations' => 0,
                'releases' => 0,
                'evictions' => 0,
            ];
        }
    }

    /**
     * Clear all pools.
     */
    public function clearAll(): void
    {
        foreach (array_keys($this->pools) as $name) {
            $this->clearPool($name);
        }
    }

    /**
     * Get memory usage.
     */
    public function getMemoryUsage(): array
    {
        $usage = [];

        foreach ($this->pools as $name => $pool) {
            $usage[$name] = $pool->getMemoryUsage();
        }

        $usage['total'] = array_sum(array_column($usage, 'bytes'));
        $usage['total_formatted'] = $this->formatBytes($usage['total']);

        return $usage;
    }

    /**
     * Format bytes to human readable.
     */
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $factor = floor((strlen((string)$bytes) - 1) / 3);
        return sprintf("%.2f %s", $bytes / pow(1024, $factor), $units[$factor]);
    }

    /**
     * Optimize pools based on usage.
     */
    public function optimize(): array
    {
        $optimizations = [];

        foreach ($this->pools as $name => $pool) {
            $hitRate = $this->calculateHitRate($name);
            $size = $pool->getSize();
            $maxSize = $pool->getMaxSize();

            // If hit rate is low and pool is full, it might be too small
            if ($hitRate < 0.5 && $size >= $maxSize * 0.9) {
                $optimizations[$name] = [
                    'recommendation' => 'increase_pool_size',
                    'current_size' => $maxSize,
                    'suggested_size' => (int)($maxSize * 1.5),
                    'hit_rate' => $hitRate,
                ];
            }

            // If pool is consistently underfilled, it might be too large
            if ($size < $maxSize * 0.3 && $this->statistics[$name]['allocations'] > 100) {
                $optimizations[$name] = [
                    'recommendation' => 'decrease_pool_size',
                    'current_size' => $maxSize,
                    'suggested_size' => (int)($maxSize * 0.5),
                    'utilization' => round($size / $maxSize, 2),
                ];
            }

            // Evict stale entries
            $pool->evictStale();
        }

        return $optimizations;
    }
}

/**
 * Resource pool implementation.
 */
class ResourcePool
{
    private string $name;
    private array $config;
    private array $items = [];
    private array $available = [];
    private array $metadata = [];
    private int $maxSize;
    private string $type;

    public function __construct(string $name, array $config)
    {
        $this->name = $name;
        $this->config = $config;
        $this->maxSize = $config['max_size'] ?? 100;
        $this->type = $config['type'] ?? 'memory';
    }

    public function acquire(): mixed
    {
        if (!empty($this->available)) {
            $key = array_pop($this->available);
            return $this->items[$key];
        }

        return $this->create();
    }

    public function release(mixed $resource, ?string $key = null): void
    {
        if ($key === null) {
            $key = spl_object_hash($resource);
        }

        $this->items[$key] = $resource;
        $this->available[] = $key;
        $this->metadata[$key] = [
            'last_used' => time(),
            'created_at' => $this->metadata[$key]['created_at'] ?? time(),
        ];
    }

    public function store(string $key, mixed $value): bool
    {
        $evicted = false;

        // Check if we need to evict
        if (count($this->items) >= $this->maxSize && !isset($this->items[$key])) {
            $this->evictOne();
            $evicted = true;
        }

        $this->items[$key] = $value;
        $this->metadata[$key] = [
            'last_used' => time(),
            'created_at' => time(),
        ];

        return $evicted;
    }

    public function get(string $key): mixed
    {
        if (!isset($this->items[$key])) {
            return null;
        }

        // Check TTL
        $ttl = $this->config['ttl'] ?? null;
        if ($ttl !== null) {
            $createdAt = $this->metadata[$key]['created_at'] ?? 0;
            if (time() - $createdAt > $ttl) {
                unset($this->items[$key], $this->metadata[$key]);
                return null;
            }
        }

        $this->metadata[$key]['last_used'] = time();
        return $this->items[$key];
    }

    public function getSize(): int
    {
        return count($this->items);
    }

    public function getMaxSize(): int
    {
        return $this->maxSize;
    }

    public function clear(): void
    {
        $this->items = [];
        $this->available = [];
        $this->metadata = [];
    }

    public function getMemoryUsage(): array
    {
        $bytes = 0;
        foreach ($this->items as $item) {
            $bytes += $this->estimateSize($item);
        }

        return [
            'items' => count($this->items),
            'bytes' => $bytes,
        ];
    }

    public function evictStale(): int
    {
        $evicted = 0;
        $ttl = $this->config['ttl'] ?? null;
        $idleTimeout = $this->config['idle_timeout'] ?? null;
        $now = time();

        foreach ($this->metadata as $key => $meta) {
            $shouldEvict = false;

            if ($ttl !== null && ($now - $meta['created_at']) > $ttl) {
                $shouldEvict = true;
            }

            if ($idleTimeout !== null && ($now - $meta['last_used']) > $idleTimeout) {
                $shouldEvict = true;
            }

            if ($shouldEvict) {
                unset($this->items[$key], $this->metadata[$key]);
                $this->available = array_filter($this->available, fn($k) => $k !== $key);
                $evicted++;
            }
        }

        return $evicted;
    }

    private function evictOne(): void
    {
        // LRU eviction
        $oldestKey = null;
        $oldestTime = PHP_INT_MAX;

        foreach ($this->metadata as $key => $meta) {
            if ($meta['last_used'] < $oldestTime) {
                $oldestTime = $meta['last_used'];
                $oldestKey = $key;
            }
        }

        if ($oldestKey !== null) {
            unset($this->items[$oldestKey], $this->metadata[$oldestKey]);
            $this->available = array_filter($this->available, fn($k) => $k !== $oldestKey);
        }
    }

    private function create(): mixed
    {
        return match ($this->type) {
            'buffer' => new Buffer($this->config['buffer_size'] ?? 65536),
            'connection' => null, // Would create actual connections
            default => new \stdClass(),
        };
    }

    private function estimateSize(mixed $item): int
    {
        if (is_string($item)) {
            return strlen($item);
        }
        if (is_array($item)) {
            return strlen(serialize($item));
        }
        if (is_object($item)) {
            return strlen(serialize($item));
        }
        return 8;
    }
}

/**
 * Compiled regex pattern.
 */
class CompiledPattern
{
    private string $pattern;
    private bool $valid;
    private ?string $error = null;

    public function __construct(string $pattern)
    {
        $this->pattern = $pattern;
        $this->valid = @preg_match($pattern, '') !== false;

        if (!$this->valid) {
            $this->error = preg_last_error_msg();
        }
    }

    public function match(string $subject): bool
    {
        if (!$this->valid) {
            return false;
        }
        return preg_match($this->pattern, $subject) === 1;
    }

    public function matchAll(string $subject): array
    {
        if (!$this->valid) {
            return [];
        }
        preg_match_all($this->pattern, $subject, $matches);
        return $matches[0] ?? [];
    }

    public function isValid(): bool
    {
        return $this->valid;
    }

    public function getError(): ?string
    {
        return $this->error;
    }
}

/**
 * Reusable buffer.
 */
class Buffer
{
    private string $data = '';
    private int $maxSize;
    private int $position = 0;

    public function __construct(int $maxSize = 65536)
    {
        $this->maxSize = $maxSize;
    }

    public function write(string $data): int
    {
        $available = $this->maxSize - strlen($this->data);
        $toWrite = substr($data, 0, $available);
        $this->data .= $toWrite;
        return strlen($toWrite);
    }

    public function read(int $length): string
    {
        $data = substr($this->data, $this->position, $length);
        $this->position += strlen($data);
        return $data;
    }

    public function getContents(): string
    {
        return $this->data;
    }

    public function reset(): void
    {
        $this->data = '';
        $this->position = 0;
    }

    public function getSize(): int
    {
        return strlen($this->data);
    }

    public function getAvailable(): int
    {
        return $this->maxSize - strlen($this->data);
    }
}
