<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\ML;

use Illuminate\Support\Facades\Cache;

/**
 * Adaptive Threshold Manager.
 *
 * Dynamically adjusts security thresholds based on:
 * - Traffic patterns and volumes
 * - Time of day/week
 * - Historical false positive/negative rates
 * - Attack trends
 * - System load
 */
class AdaptiveThresholdManager
{
    private array $config;
    private array $defaultThresholds;
    private string $cachePrefix;
    private float $learningRate;
    private float $minAdjustment;
    private float $maxAdjustment;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->cachePrefix = $config['cache_prefix'] ?? 'adaptive_threshold:';
        $this->learningRate = $config['learning_rate'] ?? 0.1;
        $this->minAdjustment = $config['min_adjustment'] ?? 0.5;
        $this->maxAdjustment = $config['max_adjustment'] ?? 2.0;

        $this->defaultThresholds = $config['default_thresholds'] ?? [
            'rate_limit' => 100,
            'payload_size' => 1048576,
            'request_rate' => 60,
            'failed_auth' => 5,
            'anomaly_score' => 2.5,
            'risk_score' => 70,
            'session_duration' => 3600,
            'concurrent_sessions' => 5,
        ];
    }

    /**
     * Get current threshold for a metric.
     */
    public function getThreshold(string $metric, array $context = []): float
    {
        $baseThreshold = $this->defaultThresholds[$metric] ?? 1.0;
        $adjustedThreshold = $this->getStoredThreshold($metric);

        if ($adjustedThreshold === null) {
            $adjustedThreshold = $baseThreshold;
        }

        // Apply contextual adjustments
        $multiplier = $this->calculateContextualMultiplier($metric, $context);
        $finalThreshold = $adjustedThreshold * $multiplier;

        // Ensure within bounds
        return max(
            $baseThreshold * $this->minAdjustment,
            min($baseThreshold * $this->maxAdjustment, $finalThreshold)
        );
    }

    /**
     * Record a detection outcome for learning.
     */
    public function recordOutcome(
        string $metric,
        float $observedValue,
        float $thresholdUsed,
        string $outcome
    ): void {
        $history = $this->getHistory($metric);

        $history[] = [
            'value' => $observedValue,
            'threshold' => $thresholdUsed,
            'outcome' => $outcome, // 'true_positive', 'false_positive', 'true_negative', 'false_negative'
            'timestamp' => time(),
            'hour' => (int)date('G'),
            'day_of_week' => (int)date('N'),
        ];

        // Keep recent history
        if (count($history) > 10000) {
            $history = array_slice($history, -10000);
        }

        $this->saveHistory($metric, $history);

        // Update threshold based on outcome
        $this->updateThreshold($metric, $observedValue, $thresholdUsed, $outcome);
    }

    /**
     * Update threshold based on outcome.
     */
    private function updateThreshold(
        string $metric,
        float $observedValue,
        float $thresholdUsed,
        string $outcome
    ): void {
        $currentThreshold = $this->getStoredThreshold($metric) ?? $thresholdUsed;

        $adjustment = match ($outcome) {
            // False positive: threshold was too aggressive, increase it
            'false_positive' => $this->learningRate,
            // False negative: threshold was too lenient, decrease it
            'false_negative' => -$this->learningRate,
            // True positive/negative: small adjustment towards observed value
            'true_positive', 'true_negative' => 0,
            default => 0,
        };

        if ($adjustment !== 0) {
            $baseThreshold = $this->defaultThresholds[$metric] ?? $currentThreshold;
            $newThreshold = $currentThreshold * (1 + $adjustment);

            // Ensure within bounds
            $newThreshold = max(
                $baseThreshold * $this->minAdjustment,
                min($baseThreshold * $this->maxAdjustment, $newThreshold)
            );

            $this->saveThreshold($metric, $newThreshold);
        }
    }

    /**
     * Calculate contextual multiplier.
     */
    private function calculateContextualMultiplier(string $metric, array $context): float
    {
        $multiplier = 1.0;

        // Time-based adjustments
        $hour = (int)date('G');
        $dayOfWeek = (int)date('N');

        // More lenient during business hours
        if ($hour >= 9 && $hour <= 17 && $dayOfWeek <= 5) {
            $multiplier *= 1.1;
        }

        // More strict during off-hours (common attack time)
        if ($hour < 6 || $hour > 22) {
            $multiplier *= 0.9;
        }

        // Weekend adjustments
        if ($dayOfWeek >= 6) {
            $multiplier *= 0.95;
        }

        // Traffic volume adjustments
        if (isset($context['traffic_volume'])) {
            $normalTraffic = $context['normal_traffic'] ?? 1000;
            $ratio = $context['traffic_volume'] / $normalTraffic;

            if ($ratio > 2) {
                // High traffic: slightly more lenient to avoid false positives
                $multiplier *= 1.2;
            } elseif ($ratio < 0.3) {
                // Low traffic: more strict
                $multiplier *= 0.8;
            }
        }

        // Active attack adjustments
        if ($context['active_attack'] ?? false) {
            $multiplier *= 0.7; // More aggressive during attacks
        }

        // Recent false positive rate
        $fpRate = $this->getRecentFalsePositiveRate($metric);
        if ($fpRate > 0.2) {
            // Too many false positives, be more lenient
            $multiplier *= 1.1;
        }

        // Recent false negative rate
        $fnRate = $this->getRecentFalseNegativeRate($metric);
        if ($fnRate > 0.1) {
            // Missing attacks, be more strict
            $multiplier *= 0.9;
        }

        return $multiplier;
    }

    /**
     * Get time-adjusted threshold.
     */
    public function getTimeAdjustedThreshold(string $metric): float
    {
        $history = $this->getHistory($metric);
        $hour = (int)date('G');
        $dayOfWeek = (int)date('N');

        // Filter history for similar time periods
        $relevantHistory = array_filter($history, function ($entry) use ($hour, $dayOfWeek) {
            $hourDiff = abs($entry['hour'] - $hour);
            $dayMatch = $entry['day_of_week'] == $dayOfWeek ||
                       ($dayOfWeek <= 5 && $entry['day_of_week'] <= 5) || // weekday
                       ($dayOfWeek >= 6 && $entry['day_of_week'] >= 6);   // weekend

            return $hourDiff <= 2 && $dayMatch;
        });

        if (count($relevantHistory) < 10) {
            return $this->getThreshold($metric);
        }

        // Calculate optimal threshold from relevant history
        $truePositives = array_filter($relevantHistory, fn($e) => $e['outcome'] === 'true_positive');
        $trueNegatives = array_filter($relevantHistory, fn($e) => $e['outcome'] === 'true_negative');

        if (empty($truePositives) || empty($trueNegatives)) {
            return $this->getThreshold($metric);
        }

        // Find threshold that best separates true positives from true negatives
        $tpValues = array_column($truePositives, 'value');
        $tnValues = array_column($trueNegatives, 'value');

        $tpMin = min($tpValues);
        $tnMax = max($tnValues);

        // Optimal threshold is midpoint between highest legitimate and lowest attack
        return ($tpMin + $tnMax) / 2;
    }

    /**
     * Get recent false positive rate.
     */
    private function getRecentFalsePositiveRate(string $metric): float
    {
        $history = $this->getHistory($metric);
        $recent = array_filter($history, fn($e) => time() - $e['timestamp'] < 3600);

        if (count($recent) < 10) {
            return 0;
        }

        $falsePositives = count(array_filter($recent, fn($e) => $e['outcome'] === 'false_positive'));
        $positives = count(array_filter($recent, fn($e) =>
            $e['outcome'] === 'true_positive' || $e['outcome'] === 'false_positive'
        ));

        return $positives > 0 ? $falsePositives / $positives : 0;
    }

    /**
     * Get recent false negative rate.
     */
    private function getRecentFalseNegativeRate(string $metric): float
    {
        $history = $this->getHistory($metric);
        $recent = array_filter($history, fn($e) => time() - $e['timestamp'] < 3600);

        if (count($recent) < 10) {
            return 0;
        }

        $falseNegatives = count(array_filter($recent, fn($e) => $e['outcome'] === 'false_negative'));
        $negatives = count(array_filter($recent, fn($e) =>
            $e['outcome'] === 'true_negative' || $e['outcome'] === 'false_negative'
        ));

        return $negatives > 0 ? $falseNegatives / $negatives : 0;
    }

    /**
     * Get threshold statistics.
     */
    public function getStatistics(string $metric): array
    {
        $history = $this->getHistory($metric);
        $currentThreshold = $this->getStoredThreshold($metric) ?? $this->defaultThresholds[$metric] ?? 0;

        $recentHour = array_filter($history, fn($e) => time() - $e['timestamp'] < 3600);

        $outcomes = [
            'true_positive' => 0,
            'false_positive' => 0,
            'true_negative' => 0,
            'false_negative' => 0,
        ];

        foreach ($recentHour as $entry) {
            if (isset($outcomes[$entry['outcome']])) {
                $outcomes[$entry['outcome']]++;
            }
        }

        $total = array_sum($outcomes);
        $accuracy = $total > 0
            ? ($outcomes['true_positive'] + $outcomes['true_negative']) / $total
            : 0;

        return [
            'metric' => $metric,
            'current_threshold' => $currentThreshold,
            'default_threshold' => $this->defaultThresholds[$metric] ?? null,
            'adjustment_factor' => $currentThreshold / ($this->defaultThresholds[$metric] ?? $currentThreshold),
            'recent_outcomes' => $outcomes,
            'accuracy' => round($accuracy, 4),
            'false_positive_rate' => round($this->getRecentFalsePositiveRate($metric), 4),
            'false_negative_rate' => round($this->getRecentFalseNegativeRate($metric), 4),
            'total_samples' => count($history),
        ];
    }

    /**
     * Get all thresholds with their current values.
     */
    public function getAllThresholds(): array
    {
        $thresholds = [];

        foreach ($this->defaultThresholds as $metric => $default) {
            $stored = $this->getStoredThreshold($metric);
            $thresholds[$metric] = [
                'default' => $default,
                'current' => $stored ?? $default,
                'adjusted' => $stored !== null,
            ];
        }

        return $thresholds;
    }

    /**
     * Reset threshold to default.
     */
    public function resetThreshold(string $metric): void
    {
        Cache::forget($this->cachePrefix . "threshold:{$metric}");
        Cache::forget($this->cachePrefix . "history:{$metric}");
    }

    /**
     * Reset all thresholds.
     */
    public function resetAll(): void
    {
        foreach (array_keys($this->defaultThresholds) as $metric) {
            $this->resetThreshold($metric);
        }
    }

    /**
     * Get stored threshold.
     */
    private function getStoredThreshold(string $metric): ?float
    {
        return Cache::get($this->cachePrefix . "threshold:{$metric}");
    }

    /**
     * Save threshold.
     */
    private function saveThreshold(string $metric, float $value): void
    {
        Cache::put($this->cachePrefix . "threshold:{$metric}", $value, 86400 * 7);
    }

    /**
     * Get history.
     */
    private function getHistory(string $metric): array
    {
        return Cache::get($this->cachePrefix . "history:{$metric}", []);
    }

    /**
     * Save history.
     */
    private function saveHistory(string $metric, array $history): void
    {
        Cache::put($this->cachePrefix . "history:{$metric}", $history, 86400 * 7);
    }
}
