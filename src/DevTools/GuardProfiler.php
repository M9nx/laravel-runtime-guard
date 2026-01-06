<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\DevTools;

use Mounir\RuntimeGuard\Contracts\GuardInterface;
use Mounir\RuntimeGuard\Context\RuntimeContext;
use Illuminate\Http\Request;

/**
 * Guard Profiler.
 *
 * Performance profiling for security guards:
 * - Execution time analysis
 * - Memory usage tracking
 * - Bottleneck identification
 * - Optimization suggestions
 */
class GuardProfiler
{
    private array $guards = [];
    private array $profiles = [];
    private array $aggregatedStats = [];
    private bool $memoryTracking;
    private bool $detailedProfiling;

    public function __construct(array $config = [])
    {
        $this->memoryTracking = $config['memory_tracking'] ?? true;
        $this->detailedProfiling = $config['detailed_profiling'] ?? true;
    }

    /**
     * Register guards for profiling.
     */
    public function registerGuards(array $guards): void
    {
        foreach ($guards as $guard) {
            if ($guard instanceof GuardInterface) {
                $this->guards[$guard->getName()] = $guard;
                $this->aggregatedStats[$guard->getName()] = [
                    'total_executions' => 0,
                    'total_time' => 0,
                    'total_memory' => 0,
                    'min_time' => PHP_FLOAT_MAX,
                    'max_time' => 0,
                    'times' => [],
                ];
            }
        }
    }

    /**
     * Profile all guards.
     */
    public function profile(RuntimeContext $context): ProfileReport
    {
        $results = [];
        $totalTime = 0;
        $totalMemory = 0;

        foreach ($this->guards as $name => $guard) {
            if (!$guard->isEnabled()) {
                continue;
            }

            $profile = $this->profileGuard($guard, $context);
            $results[$name] = $profile;
            $totalTime += $profile['execution_time'];
            $totalMemory += $profile['memory_used'];

            // Update aggregated stats
            $this->updateAggregatedStats($name, $profile);
        }

        // Sort by execution time
        uasort($results, fn($a, $b) => $b['execution_time'] <=> $a['execution_time']);

        return new ProfileReport(
            $results,
            $totalTime,
            $totalMemory,
            $this->identifyBottlenecks($results),
            $this->generateOptimizationSuggestions($results)
        );
    }

    /**
     * Profile a single guard.
     */
    private function profileGuard(GuardInterface $guard, RuntimeContext $context): array
    {
        $profile = [
            'guard' => $guard->getName(),
            'priority' => $guard->getPriority(),
            'enabled' => $guard->isEnabled(),
        ];

        // Memory tracking
        $startMemory = $this->memoryTracking ? memory_get_usage(true) : 0;

        // Detailed profiling
        $checkpoints = [];
        if ($this->detailedProfiling) {
            $checkpoints['start'] = hrtime(true);
        }

        // Execute guard
        $startTime = hrtime(true);

        try {
            $result = $guard->inspect($context);
            $profile['passed'] = $result->isPassed();
            $profile['threats_count'] = count($result->getThreats());
            $profile['error'] = null;
        } catch (\Throwable $e) {
            $profile['passed'] = null;
            $profile['error'] = $e->getMessage();
        }

        $endTime = hrtime(true);

        if ($this->detailedProfiling) {
            $checkpoints['end'] = hrtime(true);
        }

        // Calculate metrics
        $profile['execution_time'] = ($endTime - $startTime) / 1e6; // Convert to milliseconds
        $profile['memory_used'] = $this->memoryTracking
            ? memory_get_usage(true) - $startMemory
            : 0;

        if ($this->detailedProfiling && !empty($checkpoints)) {
            $profile['checkpoints'] = $checkpoints;
        }

        return $profile;
    }

    /**
     * Update aggregated statistics.
     */
    private function updateAggregatedStats(string $guardName, array $profile): void
    {
        $stats = &$this->aggregatedStats[$guardName];
        $stats['total_executions']++;
        $stats['total_time'] += $profile['execution_time'];
        $stats['total_memory'] += $profile['memory_used'];
        $stats['min_time'] = min($stats['min_time'], $profile['execution_time']);
        $stats['max_time'] = max($stats['max_time'], $profile['execution_time']);

        // Keep last 100 times for percentile calculation
        $stats['times'][] = $profile['execution_time'];
        if (count($stats['times']) > 100) {
            array_shift($stats['times']);
        }
    }

    /**
     * Identify bottleneck guards.
     */
    private function identifyBottlenecks(array $results): array
    {
        $bottlenecks = [];
        $totalTime = array_sum(array_column($results, 'execution_time'));

        if ($totalTime === 0) {
            return [];
        }

        foreach ($results as $name => $profile) {
            $percentage = ($profile['execution_time'] / $totalTime) * 100;

            if ($percentage > 30) {
                $bottlenecks[] = [
                    'guard' => $name,
                    'percentage' => round($percentage, 2),
                    'execution_time' => $profile['execution_time'],
                    'severity' => $percentage > 50 ? 'critical' : 'warning',
                ];
            }
        }

        return $bottlenecks;
    }

    /**
     * Generate optimization suggestions.
     */
    private function generateOptimizationSuggestions(array $results): array
    {
        $suggestions = [];

        foreach ($results as $name => $profile) {
            // Slow guard
            if ($profile['execution_time'] > 10) { // > 10ms
                $suggestions[] = [
                    'guard' => $name,
                    'type' => 'slow_execution',
                    'message' => "Guard '{$name}' takes {$profile['execution_time']}ms. Consider optimizing patterns or caching.",
                    'priority' => 'high',
                ];
            }

            // High memory usage
            if ($profile['memory_used'] > 1048576) { // > 1MB
                $suggestions[] = [
                    'guard' => $name,
                    'type' => 'high_memory',
                    'message' => "Guard '{$name}' uses " . $this->formatBytes($profile['memory_used']) . ". Consider streaming or chunked processing.",
                    'priority' => 'medium',
                ];
            }

            // Check for variance in aggregated stats
            if (isset($this->aggregatedStats[$name])) {
                $stats = $this->aggregatedStats[$name];
                if ($stats['max_time'] > $stats['min_time'] * 10 && $stats['total_executions'] > 10) {
                    $suggestions[] = [
                        'guard' => $name,
                        'type' => 'high_variance',
                        'message' => "Guard '{$name}' has inconsistent performance. Min: {$stats['min_time']}ms, Max: {$stats['max_time']}ms",
                        'priority' => 'medium',
                    ];
                }
            }
        }

        // General suggestions
        if (count($results) > 20) {
            $suggestions[] = [
                'type' => 'too_many_guards',
                'message' => 'Consider using guard fusion or async execution with ' . count($results) . ' guards.',
                'priority' => 'medium',
            ];
        }

        return $suggestions;
    }

    /**
     * Benchmark a specific guard with multiple runs.
     */
    public function benchmark(
        string $guardName,
        RuntimeContext $context,
        int $iterations = 100
    ): BenchmarkResult {
        if (!isset($this->guards[$guardName])) {
            throw new \InvalidArgumentException("Guard not found: {$guardName}");
        }

        $guard = $this->guards[$guardName];
        $times = [];
        $memoryUsages = [];

        // Warmup
        for ($i = 0; $i < 5; $i++) {
            $guard->inspect($context);
        }

        // Actual benchmark
        for ($i = 0; $i < $iterations; $i++) {
            gc_collect_cycles();
            $startMemory = memory_get_usage(true);
            $startTime = hrtime(true);

            $guard->inspect($context);

            $times[] = (hrtime(true) - $startTime) / 1e6;
            $memoryUsages[] = memory_get_usage(true) - $startMemory;
        }

        return new BenchmarkResult(
            $guardName,
            $iterations,
            $times,
            $memoryUsages
        );
    }

    /**
     * Compare guards performance.
     */
    public function compare(array $guardNames, RuntimeContext $context, int $iterations = 50): array
    {
        $results = [];

        foreach ($guardNames as $name) {
            if (isset($this->guards[$name])) {
                $results[$name] = $this->benchmark($name, $context, $iterations);
            }
        }

        // Sort by average time
        uasort($results, fn($a, $b) => $a->getAvgTime() <=> $b->getAvgTime());

        return [
            'benchmarks' => array_map(fn($r) => $r->toArray(), $results),
            'fastest' => array_key_first($results),
            'slowest' => array_key_last($results),
        ];
    }

    /**
     * Get aggregated statistics.
     */
    public function getAggregatedStats(?string $guardName = null): array
    {
        if ($guardName !== null) {
            $stats = $this->aggregatedStats[$guardName] ?? [];
            if (!empty($stats['times'])) {
                $stats['avg_time'] = $stats['total_time'] / max($stats['total_executions'], 1);
                $stats['p50'] = $this->percentile($stats['times'], 50);
                $stats['p95'] = $this->percentile($stats['times'], 95);
                $stats['p99'] = $this->percentile($stats['times'], 99);
            }
            return $stats;
        }

        $result = [];
        foreach ($this->aggregatedStats as $name => $stats) {
            $result[$name] = $stats;
            if (!empty($stats['times'])) {
                $result[$name]['avg_time'] = $stats['total_time'] / max($stats['total_executions'], 1);
                $result[$name]['p50'] = $this->percentile($stats['times'], 50);
                $result[$name]['p95'] = $this->percentile($stats['times'], 95);
                $result[$name]['p99'] = $this->percentile($stats['times'], 99);
            }
        }

        return $result;
    }

    /**
     * Calculate percentile.
     */
    private function percentile(array $data, float $percentile): float
    {
        sort($data);
        $index = ($percentile / 100) * (count($data) - 1);
        $lower = floor($index);
        $upper = ceil($index);

        if ($lower === $upper) {
            return $data[(int)$lower];
        }

        return $data[(int)$lower] + ($index - $lower) * ($data[(int)$upper] - $data[(int)$lower]);
    }

    /**
     * Format bytes.
     */
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $factor = floor((strlen((string)$bytes) - 1) / 3);
        return sprintf("%.2f %s", $bytes / pow(1024, $factor), $units[$factor]);
    }

    /**
     * Reset statistics.
     */
    public function resetStats(): void
    {
        foreach (array_keys($this->aggregatedStats) as $name) {
            $this->aggregatedStats[$name] = [
                'total_executions' => 0,
                'total_time' => 0,
                'total_memory' => 0,
                'min_time' => PHP_FLOAT_MAX,
                'max_time' => 0,
                'times' => [],
            ];
        }
    }
}

/**
 * Profile report.
 */
class ProfileReport
{
    public function __construct(
        public readonly array $results,
        public readonly float $totalTime,
        public readonly int $totalMemory,
        public readonly array $bottlenecks,
        public readonly array $suggestions
    ) {}

    public function toArray(): array
    {
        return [
            'total_time_ms' => round($this->totalTime, 2),
            'total_memory_bytes' => $this->totalMemory,
            'guard_count' => count($this->results),
            'bottlenecks' => $this->bottlenecks,
            'suggestions' => $this->suggestions,
            'results' => $this->results,
        ];
    }
}

/**
 * Benchmark result.
 */
class BenchmarkResult
{
    private array $times;
    private array $memoryUsages;

    public function __construct(
        public readonly string $guardName,
        public readonly int $iterations,
        array $times,
        array $memoryUsages
    ) {
        $this->times = $times;
        $this->memoryUsages = $memoryUsages;
    }

    public function getAvgTime(): float
    {
        return array_sum($this->times) / count($this->times);
    }

    public function getMinTime(): float
    {
        return min($this->times);
    }

    public function getMaxTime(): float
    {
        return max($this->times);
    }

    public function getStdDev(): float
    {
        $avg = $this->getAvgTime();
        $squaredDiffs = array_map(fn($t) => pow($t - $avg, 2), $this->times);
        return sqrt(array_sum($squaredDiffs) / count($squaredDiffs));
    }

    public function getAvgMemory(): float
    {
        return array_sum($this->memoryUsages) / count($this->memoryUsages);
    }

    public function toArray(): array
    {
        return [
            'guard' => $this->guardName,
            'iterations' => $this->iterations,
            'avg_time_ms' => round($this->getAvgTime(), 4),
            'min_time_ms' => round($this->getMinTime(), 4),
            'max_time_ms' => round($this->getMaxTime(), 4),
            'std_dev_ms' => round($this->getStdDev(), 4),
            'avg_memory_bytes' => round($this->getAvgMemory()),
        ];
    }
}
