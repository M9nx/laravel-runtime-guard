<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Analytics;

use Illuminate\Support\Facades\Cache;

/**
 * Trend Analyzer.
 *
 * Analyzes attack trends over time and provides insights.
 */
class TrendAnalyzer
{
    protected string $cachePrefix = 'rtg_trends:';

    /**
     * Record a threat occurrence.
     */
    public function recordThreat(string $guard, string $level, array $metadata = []): void
    {
        $timestamp = time();
        $hourKey = date('Y-m-d-H', $timestamp);
        $dayKey = date('Y-m-d', $timestamp);

        // Hourly counters
        $this->incrementCounter("hourly:{$guard}:{$hourKey}");
        $this->incrementCounter("hourly:level:{$level}:{$hourKey}");
        $this->incrementCounter("hourly:total:{$hourKey}");

        // Daily counters
        $this->incrementCounter("daily:{$guard}:{$dayKey}");
        $this->incrementCounter("daily:level:{$level}:{$dayKey}");
        $this->incrementCounter("daily:total:{$dayKey}");

        // Record metadata for pattern analysis
        if (isset($metadata['path'])) {
            $this->incrementCounter("paths:{$dayKey}:" . md5($metadata['path']));
        }
    }

    /**
     * Get hourly trends for past N hours.
     */
    public function getHourlyTrends(int $hours = 24, ?string $guard = null): array
    {
        $trends = [];

        for ($i = $hours - 1; $i >= 0; $i--) {
            $hourKey = date('Y-m-d-H', strtotime("-{$i} hours"));

            if ($guard) {
                $count = $this->getCounter("hourly:{$guard}:{$hourKey}");
            } else {
                $count = $this->getCounter("hourly:total:{$hourKey}");
            }

            $trends[] = [
                'hour' => $hourKey,
                'timestamp' => strtotime($hourKey . ':00:00'),
                'count' => $count,
            ];
        }

        return $trends;
    }

    /**
     * Get daily trends for past N days.
     */
    public function getDailyTrends(int $days = 30, ?string $guard = null): array
    {
        $trends = [];

        for ($i = $days - 1; $i >= 0; $i--) {
            $dayKey = date('Y-m-d', strtotime("-{$i} days"));

            if ($guard) {
                $count = $this->getCounter("daily:{$guard}:{$dayKey}");
            } else {
                $count = $this->getCounter("daily:total:{$dayKey}");
            }

            $trends[] = [
                'date' => $dayKey,
                'count' => $count,
            ];
        }

        return $trends;
    }

    /**
     * Get trends by threat level.
     */
    public function getTrendsByLevel(int $hours = 24): array
    {
        $levels = ['low', 'medium', 'high', 'critical'];
        $trends = [];

        foreach ($levels as $level) {
            $levelTrends = [];

            for ($i = $hours - 1; $i >= 0; $i--) {
                $hourKey = date('Y-m-d-H', strtotime("-{$i} hours"));
                $count = $this->getCounter("hourly:level:{$level}:{$hourKey}");
                $levelTrends[] = $count;
            }

            $trends[$level] = [
                'data' => $levelTrends,
                'total' => array_sum($levelTrends),
                'avg' => count($levelTrends) > 0 ? array_sum($levelTrends) / count($levelTrends) : 0,
                'max' => max($levelTrends) ?: 0,
            ];
        }

        return $trends;
    }

    /**
     * Detect anomalies in trends.
     */
    public function detectAnomalies(int $hours = 24, float $threshold = 2.0): array
    {
        $trends = $this->getHourlyTrends($hours);
        $counts = array_column($trends, 'count');

        if (count($counts) < 3) {
            return [];
        }

        $mean = array_sum($counts) / count($counts);
        $stddev = $this->calculateStdDev($counts, $mean);

        $anomalies = [];

        foreach ($trends as $i => $trend) {
            if ($stddev > 0) {
                $zScore = ($trend['count'] - $mean) / $stddev;

                if (abs($zScore) > $threshold) {
                    $anomalies[] = [
                        'hour' => $trend['hour'],
                        'count' => $trend['count'],
                        'z_score' => round($zScore, 2),
                        'type' => $zScore > 0 ? 'spike' : 'drop',
                        'expected_range' => [
                            'min' => max(0, round($mean - ($stddev * $threshold))),
                            'max' => round($mean + ($stddev * $threshold)),
                        ],
                    ];
                }
            }
        }

        return $anomalies;
    }

    /**
     * Get trend summary.
     */
    public function getSummary(int $hours = 24): array
    {
        $hourlyTrends = $this->getHourlyTrends($hours);
        $counts = array_column($hourlyTrends, 'count');

        $total = array_sum($counts);
        $avg = count($counts) > 0 ? $total / count($counts) : 0;

        // Calculate trend direction
        $firstHalf = array_slice($counts, 0, (int)(count($counts) / 2));
        $secondHalf = array_slice($counts, (int)(count($counts) / 2));
        $firstAvg = count($firstHalf) > 0 ? array_sum($firstHalf) / count($firstHalf) : 0;
        $secondAvg = count($secondHalf) > 0 ? array_sum($secondHalf) / count($secondHalf) : 0;

        $trendDirection = 'stable';
        if ($secondAvg > $firstAvg * 1.2) {
            $trendDirection = 'increasing';
        } elseif ($secondAvg < $firstAvg * 0.8) {
            $trendDirection = 'decreasing';
        }

        // Find peak hour
        $maxIndex = array_search(max($counts) ?: 0, $counts);
        $peakHour = $hourlyTrends[$maxIndex]['hour'] ?? null;

        return [
            'period_hours' => $hours,
            'total_threats' => $total,
            'avg_per_hour' => round($avg, 2),
            'max_per_hour' => max($counts) ?: 0,
            'min_per_hour' => min($counts) ?: 0,
            'trend_direction' => $trendDirection,
            'peak_hour' => $peakHour,
            'anomalies_detected' => count($this->detectAnomalies($hours)),
        ];
    }

    /**
     * Compare current period with previous.
     */
    public function compareWithPrevious(int $hours = 24): array
    {
        $currentTrends = $this->getHourlyTrends($hours);
        $currentTotal = array_sum(array_column($currentTrends, 'count'));

        // Get previous period
        $previousTotal = 0;
        for ($i = $hours * 2 - 1; $i >= $hours; $i--) {
            $hourKey = date('Y-m-d-H', strtotime("-{$i} hours"));
            $previousTotal += $this->getCounter("hourly:total:{$hourKey}");
        }

        $change = $previousTotal > 0
            ? (($currentTotal - $previousTotal) / $previousTotal) * 100
            : ($currentTotal > 0 ? 100 : 0);

        return [
            'current_period' => [
                'hours' => $hours,
                'total' => $currentTotal,
            ],
            'previous_period' => [
                'hours' => $hours,
                'total' => $previousTotal,
            ],
            'change_percent' => round($change, 2),
            'trend' => $change > 10 ? 'up' : ($change < -10 ? 'down' : 'stable'),
        ];
    }

    /**
     * Forecast next period based on trends.
     */
    public function forecast(int $hoursAhead = 24, int $historyHours = 168): array
    {
        $trends = $this->getHourlyTrends($historyHours);
        $counts = array_column($trends, 'count');

        if (count($counts) < 24) {
            return ['error' => 'Insufficient data for forecasting'];
        }

        // Simple moving average forecast
        $windowSize = 24; // 24-hour window
        $predictions = [];

        // Calculate hourly patterns (hour of day averages)
        $hourlyPatterns = array_fill(0, 24, []);
        foreach ($trends as $trend) {
            $hour = (int) date('G', $trend['timestamp']);
            $hourlyPatterns[$hour][] = $trend['count'];
        }

        $hourlyAverages = [];
        foreach ($hourlyPatterns as $hour => $values) {
            $hourlyAverages[$hour] = count($values) > 0 ? array_sum($values) / count($values) : 0;
        }

        // Generate predictions
        $currentTimestamp = time();
        for ($i = 1; $i <= $hoursAhead; $i++) {
            $futureTimestamp = $currentTimestamp + ($i * 3600);
            $hour = (int) date('G', $futureTimestamp);

            $predictions[] = [
                'hour' => date('Y-m-d H:00', $futureTimestamp),
                'predicted_count' => round($hourlyAverages[$hour]),
                'confidence' => 0.7, // Simplified confidence
            ];
        }

        return [
            'predictions' => $predictions,
            'method' => 'hourly_pattern_analysis',
            'history_hours' => $historyHours,
            'forecast_hours' => $hoursAhead,
            'total_predicted' => array_sum(array_column($predictions, 'predicted_count')),
        ];
    }

    /**
     * Increment counter.
     */
    protected function incrementCounter(string $key): void
    {
        $fullKey = $this->cachePrefix . $key;
        Cache::increment($fullKey);

        // Set TTL if new
        if (Cache::get($fullKey) === 1) {
            // Keep hourly data for 7 days, daily for 90 days
            $ttl = str_contains($key, 'hourly:') ? 604800 : 7776000;
            Cache::put($fullKey, 1, $ttl);
        }
    }

    /**
     * Get counter value.
     */
    protected function getCounter(string $key): int
    {
        return (int) Cache::get($this->cachePrefix . $key, 0);
    }

    /**
     * Calculate standard deviation.
     */
    protected function calculateStdDev(array $values, float $mean): float
    {
        if (count($values) < 2) {
            return 0;
        }

        $sumSquares = 0;
        foreach ($values as $value) {
            $sumSquares += pow($value - $mean, 2);
        }

        return sqrt($sumSquares / (count($values) - 1));
    }
}
