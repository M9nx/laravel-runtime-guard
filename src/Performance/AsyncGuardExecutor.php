<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Performance;

use M9nx\RuntimeGuard\Contracts\GuardInterface;
use M9nx\RuntimeGuard\Context\RuntimeContext;
use M9nx\RuntimeGuard\Results\GuardResult;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Async Guard Executor.
 *
 * Executes guards asynchronously for improved performance:
 * - Parallel execution using fibers/promises
 * - Timeout handling
 * - Graceful degradation
 * - Result aggregation
 */
class AsyncGuardExecutor
{
    private array $config;
    private float $timeout;
    private int $maxConcurrency;
    private bool $failFast;
    private array $guards;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->timeout = $config['timeout'] ?? 1.0;
        $this->maxConcurrency = $config['max_concurrency'] ?? 10;
        $this->failFast = $config['fail_fast'] ?? true;
        $this->guards = [];
    }

    /**
     * Register guards.
     */
    public function registerGuards(array $guards): void
    {
        $this->guards = [];
        foreach ($guards as $guard) {
            if ($guard instanceof GuardInterface && $guard->isEnabled()) {
                $this->guards[$guard->getName()] = $guard;
            }
        }
    }

    /**
     * Execute guards asynchronously.
     */
    public function execute(RuntimeContext $context): AsyncExecutionResult
    {
        $startTime = microtime(true);
        $results = [];
        $errors = [];
        $timedOut = [];

        // Sort guards by priority
        $sortedGuards = $this->guards;
        uasort($sortedGuards, fn($a, $b) => $b->getPriority() <=> $a->getPriority());

        // Split into batches for concurrency control
        $batches = array_chunk($sortedGuards, $this->maxConcurrency, true);

        foreach ($batches as $batch) {
            $batchResults = $this->executeBatch($batch, $context, $timedOut, $errors);
            $results = array_merge($results, $batchResults);

            // Check for fail-fast termination
            if ($this->failFast && $this->shouldTerminate($batchResults)) {
                break;
            }
        }

        $executionTime = microtime(true) - $startTime;

        return new AsyncExecutionResult(
            $results,
            $errors,
            $timedOut,
            $executionTime,
            count($this->guards) - count($results)
        );
    }

    /**
     * Execute a batch of guards.
     */
    private function executeBatch(
        array $guards,
        RuntimeContext $context,
        array &$timedOut,
        array &$errors
    ): array {
        $results = [];

        if (class_exists('Fiber')) {
            $results = $this->executeBatchWithFibers($guards, $context, $timedOut, $errors);
        } else {
            $results = $this->executeBatchSequential($guards, $context, $timedOut, $errors);
        }

        return $results;
    }

    /**
     * Execute batch using PHP 8.1 Fibers.
     */
    private function executeBatchWithFibers(
        array $guards,
        RuntimeContext $context,
        array &$timedOut,
        array &$errors
    ): array {
        $fibers = [];
        $results = [];
        $deadline = microtime(true) + $this->timeout;

        // Create fibers for each guard
        foreach ($guards as $name => $guard) {
            $fibers[$name] = new \Fiber(function () use ($guard, $context) {
                return $guard->inspect($context);
            });
        }

        // Start all fibers
        foreach ($fibers as $name => $fiber) {
            try {
                $fiber->start();
            } catch (Throwable $e) {
                $errors[$name] = $e->getMessage();
                unset($fibers[$name]);
            }
        }

        // Process fibers until all complete or timeout
        while (!empty($fibers) && microtime(true) < $deadline) {
            foreach ($fibers as $name => $fiber) {
                if ($fiber->isTerminated()) {
                    try {
                        $results[$name] = $fiber->getReturn();
                    } catch (Throwable $e) {
                        $errors[$name] = $e->getMessage();
                    }
                    unset($fibers[$name]);
                } elseif ($fiber->isSuspended()) {
                    try {
                        $fiber->resume();
                    } catch (Throwable $e) {
                        $errors[$name] = $e->getMessage();
                        unset($fibers[$name]);
                    }
                }
            }

            // Small sleep to prevent CPU spinning
            usleep(100);
        }

        // Handle timed out fibers
        foreach ($fibers as $name => $fiber) {
            $timedOut[] = $name;
            $results[$name] = $this->createTimeoutResult($name);
        }

        return $results;
    }

    /**
     * Execute batch sequentially with individual timeouts.
     */
    private function executeBatchSequential(
        array $guards,
        RuntimeContext $context,
        array &$timedOut,
        array &$errors
    ): array {
        $results = [];
        $perGuardTimeout = $this->timeout / max(count($guards), 1);

        foreach ($guards as $name => $guard) {
            $startTime = microtime(true);

            try {
                $results[$name] = $guard->inspect($context);

                $elapsed = microtime(true) - $startTime;
                if ($elapsed > $perGuardTimeout) {
                    Log::warning("Guard {$name} exceeded timeout", [
                        'elapsed' => $elapsed,
                        'timeout' => $perGuardTimeout,
                    ]);
                }
            } catch (Throwable $e) {
                $errors[$name] = $e->getMessage();
                $results[$name] = $this->createErrorResult($name, $e->getMessage());
            }
        }

        return $results;
    }

    /**
     * Execute with deferred results.
     */
    public function executeDeferred(RuntimeContext $context): DeferredResult
    {
        $cacheKey = 'async_guard:deferred:' . md5(serialize($context->toArray()));

        // Check for cached result
        $cached = Cache::get($cacheKey);
        if ($cached !== null) {
            return new DeferredResult(true, $cached);
        }

        // Start async execution
        $jobId = uniqid('guard_exec_', true);

        // Queue the execution (would integrate with Laravel Queue in production)
        $this->queueExecution($jobId, $context);

        return new DeferredResult(false, null, $jobId);
    }

    /**
     * Queue execution for background processing.
     */
    private function queueExecution(string $jobId, RuntimeContext $context): void
    {
        // In production, this would dispatch to Laravel Queue
        // For now, we execute synchronously and cache result

        $result = $this->execute($context);

        Cache::put("async_guard:result:{$jobId}", $result, 60);
    }

    /**
     * Get deferred result.
     */
    public function getDeferredResult(string $jobId): ?AsyncExecutionResult
    {
        return Cache::get("async_guard:result:{$jobId}");
    }

    /**
     * Check if execution should terminate early.
     */
    private function shouldTerminate(array $results): bool
    {
        foreach ($results as $result) {
            if ($result instanceof GuardResult && !$result->isPassed()) {
                if ($result->getSeverity() === 'critical') {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Create timeout result.
     */
    private function createTimeoutResult(string $guardName): GuardResult
    {
        return GuardResult::pass($guardName)
            ->withMetadata([
                'status' => 'timeout',
                'message' => 'Guard execution timed out',
            ]);
    }

    /**
     * Create error result.
     */
    private function createErrorResult(string $guardName, string $error): GuardResult
    {
        return GuardResult::pass($guardName)
            ->withMetadata([
                'status' => 'error',
                'message' => $error,
            ]);
    }

    /**
     * Execute with circuit breaker.
     */
    public function executeWithCircuitBreaker(
        RuntimeContext $context,
        string $circuitName = 'default'
    ): AsyncExecutionResult {
        $circuitKey = "async_guard:circuit:{$circuitName}";
        $circuit = Cache::get($circuitKey, [
            'state' => 'closed',
            'failures' => 0,
            'last_failure' => null,
            'half_open_at' => null,
        ]);

        // Check circuit state
        if ($circuit['state'] === 'open') {
            if (time() >= ($circuit['half_open_at'] ?? PHP_INT_MAX)) {
                $circuit['state'] = 'half_open';
            } else {
                // Circuit is open, return degraded result
                return $this->createDegradedResult('Circuit breaker is open');
            }
        }

        try {
            $result = $this->execute($context);

            // Success - reset circuit on success
            if (!$result->hasFailures()) {
                $circuit['state'] = 'closed';
                $circuit['failures'] = 0;
            } elseif ($circuit['state'] === 'half_open') {
                // Failure in half-open state - re-open circuit
                $circuit['state'] = 'open';
                $circuit['half_open_at'] = time() + 60;
            }

            Cache::put($circuitKey, $circuit, 300);
            return $result;

        } catch (Throwable $e) {
            $circuit['failures']++;
            $circuit['last_failure'] = time();

            if ($circuit['failures'] >= 5) {
                $circuit['state'] = 'open';
                $circuit['half_open_at'] = time() + 30;
            }

            Cache::put($circuitKey, $circuit, 300);
            throw $e;
        }
    }

    /**
     * Create degraded result for circuit breaker open state.
     */
    private function createDegradedResult(string $reason): AsyncExecutionResult
    {
        return new AsyncExecutionResult(
            [],
            [$reason],
            [],
            0,
            count($this->guards),
            true
        );
    }

    /**
     * Get execution statistics.
     */
    public function getStatistics(): array
    {
        return [
            'registered_guards' => count($this->guards),
            'timeout' => $this->timeout,
            'max_concurrency' => $this->maxConcurrency,
            'fail_fast' => $this->failFast,
            'fibers_available' => class_exists('Fiber'),
        ];
    }
}

/**
 * Async execution result.
 */
class AsyncExecutionResult
{
    public function __construct(
        public readonly array $results,
        public readonly array $errors,
        public readonly array $timedOut,
        public readonly float $executionTime,
        public readonly int $skipped,
        public readonly bool $degraded = false
    ) {}

    public function hasFailures(): bool
    {
        foreach ($this->results as $result) {
            if ($result instanceof GuardResult && !$result->isPassed()) {
                return true;
            }
        }
        return false;
    }

    public function hasErrors(): bool
    {
        return !empty($this->errors) || !empty($this->timedOut);
    }

    public function getPassedGuards(): array
    {
        return array_filter(
            $this->results,
            fn($r) => $r instanceof GuardResult && $r->isPassed()
        );
    }

    public function getFailedGuards(): array
    {
        return array_filter(
            $this->results,
            fn($r) => $r instanceof GuardResult && !$r->isPassed()
        );
    }

    public function toArray(): array
    {
        return [
            'total_guards' => count($this->results) + $this->skipped,
            'executed' => count($this->results),
            'passed' => count($this->getPassedGuards()),
            'failed' => count($this->getFailedGuards()),
            'errors' => count($this->errors),
            'timed_out' => count($this->timedOut),
            'skipped' => $this->skipped,
            'execution_time_ms' => round($this->executionTime * 1000, 2),
            'degraded' => $this->degraded,
        ];
    }
}

/**
 * Deferred result placeholder.
 */
class DeferredResult
{
    public function __construct(
        public readonly bool $ready,
        public readonly ?AsyncExecutionResult $result,
        public readonly ?string $jobId = null
    ) {}

    public function isReady(): bool
    {
        return $this->ready;
    }

    public function getResult(): ?AsyncExecutionResult
    {
        return $this->result;
    }

    public function getJobId(): ?string
    {
        return $this->jobId;
    }
}
