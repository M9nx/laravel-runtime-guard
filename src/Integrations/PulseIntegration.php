<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Integrations;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use Illuminate\Support\Facades\Cache;

/**
 * Laravel Pulse Integration.
 *
 * Records security metrics for the Pulse dashboard.
 */
class PulseIntegration
{
    protected bool $enabled;
    protected string $cachePrefix = 'rtg_pulse:';

    public function __construct()
    {
        $this->enabled = $this->isPulseAvailable() && config('runtime-guard.integrations.pulse.enabled', true);
    }

    /**
     * Check if Pulse is available.
     */
    protected function isPulseAvailable(): bool
    {
        return class_exists(\Laravel\Pulse\Pulse::class);
    }

    /**
     * Record a guard inspection result.
     */
    public function record(string $guardName, GuardResultInterface $result, array $context = []): void
    {
        if (!$this->enabled) {
            return;
        }

        // Increment counters
        $this->incrementCounter("guard:{$guardName}:total");

        if ($result->failed()) {
            $level = strtolower($result->getThreatLevel()?->name ?? 'unknown');
            $this->incrementCounter("guard:{$guardName}:blocked");
            $this->incrementCounter("threats:{$level}");
            $this->incrementCounter("threats:total");

            // Record threat detail
            $this->recordThreat($guardName, $result, $context);
        }

        // Record timing if available
        if (isset($context['duration_ms'])) {
            $this->recordTiming($guardName, $context['duration_ms']);
        }
    }

    /**
     * Record a threat for dashboard display.
     */
    protected function recordThreat(string $guardName, GuardResultInterface $result, array $context): void
    {
        $key = $this->cachePrefix . 'recent_threats';
        $threats = Cache::get($key, []);

        // Add new threat to front
        array_unshift($threats, [
            'guard' => $guardName,
            'level' => $result->getThreatLevel()?->name,
            'message' => $result->getMessage(),
            'path' => $context['path'] ?? null,
            'ip' => $context['ip'] ?? null,
            'timestamp' => time(),
        ]);

        // Keep only last 100 threats
        $threats = array_slice($threats, 0, 100);

        Cache::put($key, $threats, 3600);
    }

    /**
     * Increment a metric counter.
     */
    protected function incrementCounter(string $metric): void
    {
        $key = $this->cachePrefix . "counter:{$metric}";
        $hourKey = $key . ':' . date('Y-m-d-H');

        // Increment hourly counter
        Cache::increment($hourKey);

        // Set expiration if new key
        if (Cache::get($hourKey) === 1) {
            Cache::put($hourKey, 1, 86400); // Keep for 24 hours
        }
    }

    /**
     * Record timing for a guard.
     */
    protected function recordTiming(string $guardName, float $durationMs): void
    {
        $key = $this->cachePrefix . "timing:{$guardName}";
        $timings = Cache::get($key, []);

        $timings[] = [
            'duration' => $durationMs,
            'timestamp' => time(),
        ];

        // Keep last 1000 timings
        $timings = array_slice($timings, -1000);

        Cache::put($key, $timings, 3600);
    }

    /**
     * Get metrics for dashboard.
     */
    public function getMetrics(): array
    {
        return [
            'threats' => $this->getThreatMetrics(),
            'guards' => $this->getGuardMetrics(),
            'recent_threats' => $this->getRecentThreats(),
            'timing' => $this->getTimingMetrics(),
        ];
    }

    /**
     * Get threat level metrics.
     */
    protected function getThreatMetrics(): array
    {
        $levels = ['low', 'medium', 'high', 'critical'];
        $metrics = ['total' => 0];

        foreach ($levels as $level) {
            $count = $this->getHourlyTotal("threats:{$level}");
            $metrics[$level] = $count;
            $metrics['total'] += $count;
        }

        return $metrics;
    }

    /**
     * Get per-guard metrics.
     */
    protected function getGuardMetrics(): array
    {
        $guards = config('runtime-guard.guards', []);
        $metrics = [];

        foreach (array_keys($guards) as $guard) {
            $metrics[$guard] = [
                'total' => $this->getHourlyTotal("guard:{$guard}:total"),
                'blocked' => $this->getHourlyTotal("guard:{$guard}:blocked"),
            ];
        }

        return $metrics;
    }

    /**
     * Get recent threats.
     */
    protected function getRecentThreats(int $limit = 20): array
    {
        $threats = Cache::get($this->cachePrefix . 'recent_threats', []);

        return array_slice($threats, 0, $limit);
    }

    /**
     * Get timing metrics.
     */
    protected function getTimingMetrics(): array
    {
        $guards = config('runtime-guard.guards', []);
        $metrics = [];

        foreach (array_keys($guards) as $guard) {
            $key = $this->cachePrefix . "timing:{$guard}";
            $timings = Cache::get($key, []);

            if (empty($timings)) {
                continue;
            }

            $durations = array_column($timings, 'duration');
            $metrics[$guard] = [
                'avg_ms' => round(array_sum($durations) / count($durations), 3),
                'max_ms' => round(max($durations), 3),
                'min_ms' => round(min($durations), 3),
                'count' => count($durations),
            ];
        }

        return $metrics;
    }

    /**
     * Get hourly total for a metric.
     */
    protected function getHourlyTotal(string $metric, int $hours = 24): int
    {
        $total = 0;
        $baseKey = $this->cachePrefix . "counter:{$metric}";

        for ($i = 0; $i < $hours; $i++) {
            $hourKey = $baseKey . ':' . date('Y-m-d-H', strtotime("-{$i} hours"));
            $total += (int) Cache::get($hourKey, 0);
        }

        return $total;
    }

    /**
     * Check if integration is enabled.
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * Clear all metrics.
     */
    public function clearMetrics(): void
    {
        // Clear recent threats
        Cache::forget($this->cachePrefix . 'recent_threats');

        // Note: Hourly counters will naturally expire after 24 hours
    }
}
