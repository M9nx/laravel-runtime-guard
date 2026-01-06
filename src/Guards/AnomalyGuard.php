<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;
use Illuminate\Support\Facades\Cache;

/**
 * Behavioral Anomaly Detection Guard.
 *
 * Establishes baselines and detects statistical outliers in request patterns.
 */
class AnomalyGuard extends AbstractGuard
{
    protected const CACHE_PREFIX = 'runtime_guard_anomaly:';
    protected const BASELINE_WINDOW = 3600; // 1 hour
    protected const MIN_SAMPLES = 10;

    protected float $deviationThreshold;
    protected bool $learningMode;
    protected array $trackedMetrics;

    public function getName(): string
    {
        return 'anomaly';
    }

    public function onBoot(): void
    {
        parent::onBoot();

        $this->deviationThreshold = (float) config('runtime-guard.guards.anomaly.deviation_threshold', 3.0);
        $this->learningMode = (bool) config('runtime-guard.guards.anomaly.learning_mode', false);
        $this->trackedMetrics = config('runtime-guard.guards.anomaly.tracked_metrics', [
            'request_size',
            'parameter_count',
            'unique_ips',
            'requests_per_minute',
            'input_entropy',
        ]);
    }

    protected function getPatterns(): array
    {
        return []; // Anomaly detection doesn't use regex patterns
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        $metrics = $this->collectMetrics($input, $context);
        $anomalies = [];

        foreach ($metrics as $metric => $value) {
            if (!in_array($metric, $this->trackedMetrics)) {
                continue;
            }

            $baseline = $this->getBaseline($metric);

            // Update baseline
            $this->updateBaseline($metric, $value);

            // Skip if in learning mode or not enough samples
            if ($this->learningMode || $baseline['count'] < self::MIN_SAMPLES) {
                continue;
            }

            // Check for anomaly using z-score
            $zScore = $this->calculateZScore($value, $baseline['mean'], $baseline['stddev']);

            if (abs($zScore) > $this->deviationThreshold) {
                $anomalies[] = [
                    'metric' => $metric,
                    'value' => $value,
                    'mean' => $baseline['mean'],
                    'stddev' => $baseline['stddev'],
                    'z_score' => $zScore,
                ];
            }
        }

        if (!empty($anomalies)) {
            return $this->threat(
                'Behavioral anomaly detected',
                $this->assessThreatLevel($anomalies),
                [
                    'type' => 'behavioral_anomaly',
                    'anomalies' => $anomalies,
                    'deviation_threshold' => $this->deviationThreshold,
                ]
            );
        }

        return $this->pass();
    }

    /**
     * Collect current request metrics.
     */
    protected function collectMetrics(mixed $input, array $context): array
    {
        $metrics = [];

        // Request size
        $metrics['request_size'] = $this->calculateSize($input);

        // Parameter count
        $metrics['parameter_count'] = $this->countParameters($input);

        // Input entropy
        $metrics['input_entropy'] = $this->calculateEntropy($input);

        // Request timing (if available)
        if (isset($context['timestamp'])) {
            $metrics['hour_of_day'] = (int) date('G', $context['timestamp']);
            $metrics['day_of_week'] = (int) date('N', $context['timestamp']);
        }

        // IP-based metrics (if available)
        if (isset($context['ip'])) {
            $metrics['ip_request_count'] = $this->getIpRequestCount($context['ip']);
        }

        // URL-based metrics
        if (isset($context['path'])) {
            $metrics['path_segment_count'] = substr_count($context['path'], '/');
            $metrics['query_string_length'] = strlen($context['query_string'] ?? '');
        }

        return $metrics;
    }

    /**
     * Calculate size of input.
     */
    protected function calculateSize(mixed $input): int
    {
        if (is_string($input)) {
            return strlen($input);
        }

        if (is_array($input)) {
            return strlen(json_encode($input) ?: '');
        }

        return 0;
    }

    /**
     * Count parameters in input.
     */
    protected function countParameters(mixed $input): int
    {
        if (is_array($input)) {
            return $this->countArrayElements($input);
        }

        if (is_string($input)) {
            // Try to parse as query string
            parse_str($input, $parsed);
            if (!empty($parsed)) {
                return count($parsed);
            }
        }

        return 1;
    }

    /**
     * Recursively count array elements.
     */
    protected function countArrayElements(array $arr, int $depth = 0): int
    {
        if ($depth > 10) {
            return 0;
        }

        $count = 0;
        foreach ($arr as $value) {
            $count++;
            if (is_array($value)) {
                $count += $this->countArrayElements($value, $depth + 1);
            }
        }

        return $count;
    }

    /**
     * Calculate Shannon entropy of input.
     */
    protected function calculateEntropy(mixed $input): float
    {
        $string = is_string($input) ? $input : json_encode($input);
        if (empty($string)) {
            return 0.0;
        }

        $len = strlen($string);
        $frequencies = array_count_values(str_split($string));
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        return round($entropy, 4);
    }

    /**
     * Get IP request count from cache.
     */
    protected function getIpRequestCount(string $ip): int
    {
        $key = self::CACHE_PREFIX . "ip_count:{$ip}";
        $count = Cache::get($key, 0);
        Cache::put($key, $count + 1, 60); // 1 minute window

        return $count + 1;
    }

    /**
     * Get baseline statistics for a metric.
     */
    protected function getBaseline(string $metric): array
    {
        $key = self::CACHE_PREFIX . "baseline:{$metric}";

        return Cache::get($key, [
            'count' => 0,
            'sum' => 0,
            'sum_sq' => 0,
            'mean' => 0,
            'stddev' => 1,
        ]);
    }

    /**
     * Update baseline with new value using Welford's algorithm.
     */
    protected function updateBaseline(string $metric, float $value): void
    {
        $key = self::CACHE_PREFIX . "baseline:{$metric}";
        $baseline = $this->getBaseline($metric);

        $baseline['count']++;
        $delta = $value - $baseline['mean'];
        $baseline['mean'] += $delta / $baseline['count'];
        $delta2 = $value - $baseline['mean'];
        $baseline['sum_sq'] += $delta * $delta2;

        // Calculate standard deviation
        if ($baseline['count'] > 1) {
            $variance = $baseline['sum_sq'] / ($baseline['count'] - 1);
            $baseline['stddev'] = max(sqrt($variance), 0.001); // Prevent division by zero
        }

        // Keep baseline for window duration
        Cache::put($key, $baseline, self::BASELINE_WINDOW);
    }

    /**
     * Calculate z-score for a value.
     */
    protected function calculateZScore(float $value, float $mean, float $stddev): float
    {
        if ($stddev == 0) {
            return 0;
        }

        return ($value - $mean) / $stddev;
    }

    /**
     * Assess threat level based on anomalies.
     */
    protected function assessThreatLevel(array $anomalies): ThreatLevel
    {
        $maxZScore = 0;
        foreach ($anomalies as $anomaly) {
            $maxZScore = max($maxZScore, abs($anomaly['z_score']));
        }

        // Multiple anomalies increase severity
        $count = count($anomalies);

        if ($maxZScore > 5 || $count >= 3) {
            return ThreatLevel::CRITICAL;
        }

        if ($maxZScore > 4 || $count >= 2) {
            return ThreatLevel::HIGH;
        }

        return ThreatLevel::MEDIUM;
    }

    /**
     * Reset baseline for a metric.
     */
    public function resetBaseline(?string $metric = null): void
    {
        if ($metric) {
            Cache::forget(self::CACHE_PREFIX . "baseline:{$metric}");
        } else {
            foreach ($this->trackedMetrics as $m) {
                Cache::forget(self::CACHE_PREFIX . "baseline:{$m}");
            }
        }
    }

    /**
     * Export current baselines.
     */
    public function exportBaselines(): array
    {
        $baselines = [];
        foreach ($this->trackedMetrics as $metric) {
            $baselines[$metric] = $this->getBaseline($metric);
        }

        return $baselines;
    }
}
