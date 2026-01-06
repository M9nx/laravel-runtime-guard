<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Support;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;

/**
 * In-memory LRU cache for deduplicating repeated inspections.
 */
final class DeduplicationCache
{
    /**
     * @var array<string, array{result: GuardResultInterface, timestamp: int}>
     */
    private array $cache = [];

    /**
     * @var array<string, int>
     */
    private array $accessOrder = [];

    private int $accessCounter = 0;

    public function __construct(
        private readonly int $maxEntries = 1000,
        private readonly int $ttlSeconds = 60,
    ) {}

    /**
     * Get cached result for input hash.
     */
    public function get(string $hash): ?GuardResultInterface
    {
        if (! isset($this->cache[$hash])) {
            return null;
        }

        $entry = $this->cache[$hash];

        // Check TTL
        if (time() - $entry['timestamp'] > $this->ttlSeconds) {
            unset($this->cache[$hash], $this->accessOrder[$hash]);

            return null;
        }

        // Update access order for LRU
        $this->accessOrder[$hash] = ++$this->accessCounter;

        return $entry['result'];
    }

    /**
     * Store result for input hash.
     */
    public function put(string $hash, GuardResultInterface $result): void
    {
        // Evict if at capacity
        if (count($this->cache) >= $this->maxEntries && ! isset($this->cache[$hash])) {
            $this->evictLru();
        }

        $this->cache[$hash] = [
            'result' => $result,
            'timestamp' => time(),
        ];

        $this->accessOrder[$hash] = ++$this->accessCounter;
    }

    /**
     * Check if hash exists and is valid.
     */
    public function has(string $hash): bool
    {
        return $this->get($hash) !== null;
    }

    /**
     * Remove entry by hash.
     */
    public function forget(string $hash): void
    {
        unset($this->cache[$hash], $this->accessOrder[$hash]);
    }

    /**
     * Clear all cached entries.
     */
    public function flush(): void
    {
        $this->cache = [];
        $this->accessOrder = [];
        $this->accessCounter = 0;
    }

    /**
     * Get cache statistics.
     *
     * @return array{entries: int, max_entries: int, ttl: int}
     */
    public function stats(): array
    {
        // Clean expired entries first
        $this->cleanExpired();

        return [
            'entries' => count($this->cache),
            'max_entries' => $this->maxEntries,
            'ttl' => $this->ttlSeconds,
        ];
    }

    /**
     * Generate hash for input.
     */
    public static function hash(mixed $input, string $guardName = ''): string
    {
        $data = $guardName . ':' . (is_string($input) ? $input : json_encode($input));

        return hash('xxh3', $data);
    }

    /**
     * Evict least recently used entry.
     */
    private function evictLru(): void
    {
        if (empty($this->accessOrder)) {
            return;
        }

        // Find entry with lowest access counter
        $lruHash = array_search(min($this->accessOrder), $this->accessOrder, true);

        if ($lruHash !== false) {
            unset($this->cache[$lruHash], $this->accessOrder[$lruHash]);
        }
    }

    /**
     * Remove expired entries.
     */
    private function cleanExpired(): void
    {
        $now = time();

        foreach ($this->cache as $hash => $entry) {
            if ($now - $entry['timestamp'] > $this->ttlSeconds) {
                unset($this->cache[$hash], $this->accessOrder[$hash]);
            }
        }
    }
}
