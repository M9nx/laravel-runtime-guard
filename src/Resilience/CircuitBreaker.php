<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Resilience;

use Psr\SimpleCache\CacheInterface;

/**
 * Circuit breaker pattern for guard fault tolerance.
 * 
 * Prevents cascade failures by temporarily disabling failing guards.
 * States: CLOSED (normal) → OPEN (disabled) → HALF_OPEN (testing)
 */
class CircuitBreaker
{
    public const STATE_CLOSED = 'closed';
    public const STATE_OPEN = 'open';
    public const STATE_HALF_OPEN = 'half_open';

    private ?CacheInterface $cache;
    private int $failureThreshold;
    private int $recoverySeconds;
    private int $halfOpenRequests;
    private string $cachePrefix = 'runtime_guard:circuit:';

    /**
     * In-memory state for non-cached operation.
     *
     * @var array<string, array{failures: int, state: string, opened_at: ?int, half_open_successes: int}>
     */
    private array $states = [];

    public function __construct(
        ?CacheInterface $cache = null,
        int $failureThreshold = 5,
        int $recoverySeconds = 60,
        int $halfOpenRequests = 3
    ) {
        $this->cache = $cache;
        $this->failureThreshold = $failureThreshold;
        $this->recoverySeconds = $recoverySeconds;
        $this->halfOpenRequests = $halfOpenRequests;
    }

    /**
     * Create from configuration array.
     */
    public static function fromConfig(array $config, ?CacheInterface $cache = null): self
    {
        return new self(
            cache: $cache,
            failureThreshold: $config['failure_threshold'] ?? 5,
            recoverySeconds: $config['recovery_seconds'] ?? 60,
            halfOpenRequests: $config['half_open_requests'] ?? 3
        );
    }

    /**
     * Check if guard is allowed to execute.
     */
    public function isAvailable(string $guardName): bool
    {
        $state = $this->getState($guardName);

        return match ($state['state']) {
            self::STATE_CLOSED => true,
            self::STATE_OPEN => $this->shouldAttemptRecovery($state),
            self::STATE_HALF_OPEN => $state['half_open_successes'] < $this->halfOpenRequests,
            default => true,
        };
    }

    /**
     * Record successful execution.
     */
    public function recordSuccess(string $guardName): void
    {
        $state = $this->getState($guardName);

        if ($state['state'] === self::STATE_HALF_OPEN) {
            $state['half_open_successes']++;

            if ($state['half_open_successes'] >= $this->halfOpenRequests) {
                // Recovery successful, close circuit
                $state = $this->createClosedState();
            }
        } elseif ($state['state'] === self::STATE_CLOSED) {
            // Reset failure count on success
            $state['failures'] = max(0, $state['failures'] - 1);
        }

        $this->setState($guardName, $state);
    }

    /**
     * Record failed execution.
     */
    public function recordFailure(string $guardName): void
    {
        $state = $this->getState($guardName);

        if ($state['state'] === self::STATE_HALF_OPEN) {
            // Failure during recovery, reopen circuit
            $state = $this->createOpenState();
        } elseif ($state['state'] === self::STATE_CLOSED) {
            $state['failures']++;

            if ($state['failures'] >= $this->failureThreshold) {
                $state = $this->createOpenState();
            }
        }

        $this->setState($guardName, $state);
    }

    /**
     * Get current circuit state for a guard.
     */
    public function getCircuitState(string $guardName): string
    {
        return $this->getState($guardName)['state'];
    }

    /**
     * Force circuit to specific state.
     */
    public function forceState(string $guardName, string $state): void
    {
        $this->setState($guardName, match ($state) {
            self::STATE_OPEN => $this->createOpenState(),
            self::STATE_HALF_OPEN => $this->createHalfOpenState(),
            default => $this->createClosedState(),
        });
    }

    /**
     * Reset circuit to closed state.
     */
    public function reset(string $guardName): void
    {
        $this->setState($guardName, $this->createClosedState());
    }

    /**
     * Get statistics for all tracked guards.
     *
     * @return array<string, array{state: string, failures: int}>
     */
    public function getStats(): array
    {
        $stats = [];

        foreach ($this->states as $guardName => $state) {
            $stats[$guardName] = [
                'state' => $state['state'],
                'failures' => $state['failures'],
            ];
        }

        return $stats;
    }

    /**
     * Check if recovery should be attempted.
     */
    private function shouldAttemptRecovery(array $state): bool
    {
        if ($state['opened_at'] === null) {
            return false;
        }

        $elapsed = time() - $state['opened_at'];

        if ($elapsed >= $this->recoverySeconds) {
            return true;
        }

        return false;
    }

    /**
     * Transition to half-open state for recovery attempt.
     */
    public function attemptRecovery(string $guardName): void
    {
        $state = $this->getState($guardName);

        if ($state['state'] === self::STATE_OPEN && $this->shouldAttemptRecovery($state)) {
            $this->setState($guardName, $this->createHalfOpenState());
        }
    }

    /**
     * Get state from cache or memory.
     *
     * @return array{failures: int, state: string, opened_at: ?int, half_open_successes: int}
     */
    private function getState(string $guardName): array
    {
        if ($this->cache) {
            $cached = $this->cache->get($this->cachePrefix . $guardName);
            if ($cached !== null) {
                return $cached;
            }
        }

        return $this->states[$guardName] ?? $this->createClosedState();
    }

    /**
     * Set state in cache and memory.
     */
    private function setState(string $guardName, array $state): void
    {
        $this->states[$guardName] = $state;

        if ($this->cache) {
            $this->cache->set(
                $this->cachePrefix . $guardName,
                $state,
                $this->recoverySeconds * 2
            );
        }
    }

    /**
     * Create closed state.
     *
     * @return array{failures: int, state: string, opened_at: ?int, half_open_successes: int}
     */
    private function createClosedState(): array
    {
        return [
            'failures' => 0,
            'state' => self::STATE_CLOSED,
            'opened_at' => null,
            'half_open_successes' => 0,
        ];
    }

    /**
     * Create open state.
     *
     * @return array{failures: int, state: string, opened_at: ?int, half_open_successes: int}
     */
    private function createOpenState(): array
    {
        return [
            'failures' => $this->failureThreshold,
            'state' => self::STATE_OPEN,
            'opened_at' => time(),
            'half_open_successes' => 0,
        ];
    }

    /**
     * Create half-open state.
     *
     * @return array{failures: int, state: string, opened_at: ?int, half_open_successes: int}
     */
    private function createHalfOpenState(): array
    {
        return [
            'failures' => 0,
            'state' => self::STATE_HALF_OPEN,
            'opened_at' => null,
            'half_open_successes' => 0,
        ];
    }
}
