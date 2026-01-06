<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Support;

/**
 * Zero-allocation circular buffer for event storage.
 *
 * Fixed-size ring buffer that overwrites oldest entries when full.
 * Provides O(1) insertion and bounded memory usage.
 */
class RingBuffer implements \Countable, \IteratorAggregate
{
    /**
     * @var array<int, mixed>
     */
    private array $buffer;

    private int $capacity;
    private int $head = 0;
    private int $tail = 0;
    private int $count = 0;

    /**
     * Callback for evicted items.
     *
     * @var callable|null
     */
    private $onEvict = null;

    public function __construct(int $capacity = 1000)
    {
        $this->capacity = max(1, $capacity);
        $this->buffer = array_fill(0, $this->capacity, null);
    }

    /**
     * Create from configuration.
     */
    public static function fromConfig(array $config): self
    {
        $instance = new self($config['size'] ?? 1000);

        if (isset($config['on_evict']) && is_callable($config['on_evict'])) {
            $instance->onEvict($config['on_evict']);
        }

        return $instance;
    }

    /**
     * Set eviction callback.
     */
    public function onEvict(callable $callback): self
    {
        $this->onEvict = $callback;
        return $this;
    }

    /**
     * Push item to buffer.
     */
    public function push(mixed $item): self
    {
        // Handle eviction if buffer is full
        if ($this->count === $this->capacity) {
            $evicted = $this->buffer[$this->tail];

            if ($this->onEvict !== null && $evicted !== null) {
                ($this->onEvict)($evicted);
            }

            $this->tail = ($this->tail + 1) % $this->capacity;
        } else {
            $this->count++;
        }

        $this->buffer[$this->head] = $item;
        $this->head = ($this->head + 1) % $this->capacity;

        return $this;
    }

    /**
     * Get item at index (0 = oldest).
     */
    public function get(int $index): mixed
    {
        if ($index < 0 || $index >= $this->count) {
            return null;
        }

        $actualIndex = ($this->tail + $index) % $this->capacity;
        return $this->buffer[$actualIndex];
    }

    /**
     * Get the most recent item.
     */
    public function latest(): mixed
    {
        if ($this->count === 0) {
            return null;
        }

        $index = ($this->head - 1 + $this->capacity) % $this->capacity;
        return $this->buffer[$index];
    }

    /**
     * Get the oldest item.
     */
    public function oldest(): mixed
    {
        if ($this->count === 0) {
            return null;
        }

        return $this->buffer[$this->tail];
    }

    /**
     * Get the last N items (most recent first).
     *
     * @return array<mixed>
     */
    public function lastN(int $n): array
    {
        $n = min($n, $this->count);
        $items = [];

        for ($i = 0; $i < $n; $i++) {
            $index = ($this->head - 1 - $i + $this->capacity) % $this->capacity;
            $items[] = $this->buffer[$index];
        }

        return $items;
    }

    /**
     * Get all items as array (oldest first).
     *
     * @return array<mixed>
     */
    public function toArray(): array
    {
        $items = [];

        for ($i = 0; $i < $this->count; $i++) {
            $index = ($this->tail + $i) % $this->capacity;
            $items[] = $this->buffer[$index];
        }

        return $items;
    }

    /**
     * Filter items matching predicate.
     *
     * @return array<mixed>
     */
    public function filter(callable $predicate): array
    {
        $items = [];

        for ($i = 0; $i < $this->count; $i++) {
            $index = ($this->tail + $i) % $this->capacity;
            $item = $this->buffer[$index];

            if ($predicate($item)) {
                $items[] = $item;
            }
        }

        return $items;
    }

    /**
     * Find first item matching predicate.
     */
    public function find(callable $predicate): mixed
    {
        for ($i = 0; $i < $this->count; $i++) {
            $index = ($this->tail + $i) % $this->capacity;
            $item = $this->buffer[$index];

            if ($predicate($item)) {
                return $item;
            }
        }

        return null;
    }

    /**
     * Count items matching predicate.
     */
    public function countWhere(callable $predicate): int
    {
        $count = 0;

        for ($i = 0; $i < $this->count; $i++) {
            $index = ($this->tail + $i) % $this->capacity;

            if ($predicate($this->buffer[$index])) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Clear all items.
     */
    public function clear(): self
    {
        $this->buffer = array_fill(0, $this->capacity, null);
        $this->head = 0;
        $this->tail = 0;
        $this->count = 0;

        return $this;
    }

    /**
     * Flush all items through eviction callback and clear.
     */
    public function flush(): self
    {
        if ($this->onEvict !== null) {
            foreach ($this->toArray() as $item) {
                ($this->onEvict)($item);
            }
        }

        return $this->clear();
    }

    /**
     * Check if buffer is empty.
     */
    public function isEmpty(): bool
    {
        return $this->count === 0;
    }

    /**
     * Check if buffer is full.
     */
    public function isFull(): bool
    {
        return $this->count === $this->capacity;
    }

    /**
     * Get capacity.
     */
    public function capacity(): int
    {
        return $this->capacity;
    }

    /**
     * Get current count.
     */
    public function count(): int
    {
        return $this->count;
    }

    /**
     * Get statistics.
     */
    public function stats(): array
    {
        return [
            'capacity' => $this->capacity,
            'count' => $this->count,
            'utilization' => $this->capacity > 0 ? round($this->count / $this->capacity, 2) : 0,
            'is_full' => $this->isFull(),
        ];
    }

    /**
     * Iterator implementation.
     */
    public function getIterator(): \Traversable
    {
        for ($i = 0; $i < $this->count; $i++) {
            $index = ($this->tail + $i) % $this->capacity;
            yield $i => $this->buffer[$index];
        }
    }

    /**
     * Serialize buffer state.
     */
    public function serialize(): string
    {
        return serialize([
            'buffer' => $this->toArray(),
            'capacity' => $this->capacity,
        ]);
    }

    /**
     * Restore buffer state.
     */
    public static function unserialize(string $data): self
    {
        $state = unserialize($data);
        $instance = new self($state['capacity']);

        foreach ($state['buffer'] as $item) {
            $instance->push($item);
        }

        return $instance;
    }
}
