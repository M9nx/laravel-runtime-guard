<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\ML;

use Mounir\RuntimeGuard\Support\RingBuffer;
use Illuminate\Support\Facades\Cache;

/**
 * ML Anomaly Detector.
 *
 * Implements statistical and ML-based anomaly detection:
 * - Isolation Forest algorithm (simplified)
 * - Statistical outlier detection (Z-score, IQR)
 * - Time-series anomaly detection
 * - Multi-dimensional feature analysis
 */
class MLAnomalyDetector
{
    private array $config;
    private array $featureWeights;
    private int $historySize;
    private float $anomalyThreshold;
    private string $cachePrefix;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->historySize = $config['history_size'] ?? 1000;
        $this->anomalyThreshold = $config['anomaly_threshold'] ?? 2.5;
        $this->cachePrefix = $config['cache_prefix'] ?? 'ml_anomaly:';
        $this->featureWeights = $config['feature_weights'] ?? [
            'request_rate' => 0.25,
            'payload_size' => 0.15,
            'response_time' => 0.20,
            'error_rate' => 0.20,
            'unique_endpoints' => 0.10,
            'user_agent_changes' => 0.10,
        ];
    }

    /**
     * Detect anomalies in request features.
     */
    public function detect(array $features, string $entityId): AnomalyResult
    {
        $history = $this->getHistory($entityId);
        $this->addToHistory($entityId, $features);

        if (count($history) < 10) {
            return new AnomalyResult(false, 0, 'Insufficient data for analysis');
        }

        // Calculate anomaly scores using multiple methods
        $scores = [
            'zscore' => $this->calculateZScoreAnomaly($features, $history),
            'iqr' => $this->calculateIQRAnomaly($features, $history),
            'isolation' => $this->calculateIsolationScore($features, $history),
            'temporal' => $this->calculateTemporalAnomaly($features, $history),
        ];

        // Weighted ensemble of all scores
        $finalScore = $this->ensembleScore($scores);

        $isAnomaly = $finalScore > $this->anomalyThreshold;
        $anomalousFeatures = $this->identifyAnomalousFeatures($features, $history);

        return new AnomalyResult(
            $isAnomaly,
            $finalScore,
            $isAnomaly ? 'Anomalous behavior detected' : 'Normal behavior',
            $scores,
            $anomalousFeatures
        );
    }

    /**
     * Calculate Z-score based anomaly.
     */
    private function calculateZScoreAnomaly(array $features, array $history): float
    {
        $totalScore = 0;
        $featureCount = 0;

        foreach ($features as $key => $value) {
            if (!is_numeric($value)) {
                continue;
            }

            $historicalValues = array_column($history, $key);
            if (count($historicalValues) < 5) {
                continue;
            }

            $mean = array_sum($historicalValues) / count($historicalValues);
            $variance = $this->calculateVariance($historicalValues, $mean);
            $stdDev = sqrt($variance);

            if ($stdDev > 0) {
                $zScore = abs(($value - $mean) / $stdDev);
                $weight = $this->featureWeights[$key] ?? 0.1;
                $totalScore += $zScore * $weight;
                $featureCount++;
            }
        }

        return $featureCount > 0 ? $totalScore / $featureCount : 0;
    }

    /**
     * Calculate IQR-based anomaly.
     */
    private function calculateIQRAnomaly(array $features, array $history): float
    {
        $totalScore = 0;
        $featureCount = 0;

        foreach ($features as $key => $value) {
            if (!is_numeric($value)) {
                continue;
            }

            $historicalValues = array_column($history, $key);
            if (count($historicalValues) < 10) {
                continue;
            }

            sort($historicalValues);
            $q1 = $this->percentile($historicalValues, 25);
            $q3 = $this->percentile($historicalValues, 75);
            $iqr = $q3 - $q1;

            if ($iqr > 0) {
                $lowerBound = $q1 - (1.5 * $iqr);
                $upperBound = $q3 + (1.5 * $iqr);

                if ($value < $lowerBound || $value > $upperBound) {
                    $deviation = $value < $lowerBound
                        ? ($lowerBound - $value) / $iqr
                        : ($value - $upperBound) / $iqr;

                    $weight = $this->featureWeights[$key] ?? 0.1;
                    $totalScore += $deviation * $weight;
                    $featureCount++;
                }
            }
        }

        return $featureCount > 0 ? $totalScore : 0;
    }

    /**
     * Calculate simplified Isolation Forest score.
     */
    private function calculateIsolationScore(array $features, array $history): float
    {
        // Simplified isolation scoring based on how "easy" it is to isolate this point
        $isolationDepths = [];
        $numTrees = 10;

        for ($t = 0; $t < $numTrees; $t++) {
            $depth = $this->isolatePoint($features, $history, 0, 20);
            $isolationDepths[] = $depth;
        }

        // Average path length
        $avgPathLength = array_sum($isolationDepths) / count($isolationDepths);

        // Expected path length for random isolation
        $n = count($history);
        $expectedLength = $n > 1 ? 2 * (log($n - 1) + 0.5772156649) - (2 * ($n - 1) / $n) : 0;

        if ($expectedLength > 0) {
            // Score: shorter paths = more anomalous
            return pow(2, -$avgPathLength / $expectedLength);
        }

        return 0;
    }

    /**
     * Simulate isolation of a point.
     */
    private function isolatePoint(array $point, array $data, int $depth, int $maxDepth): int
    {
        if ($depth >= $maxDepth || count($data) <= 1) {
            return $depth;
        }

        // Select random feature
        $numericFeatures = array_keys(array_filter($point, 'is_numeric'));
        if (empty($numericFeatures)) {
            return $depth;
        }

        $feature = $numericFeatures[array_rand($numericFeatures)];
        $featureValues = array_column($data, $feature);

        if (empty($featureValues)) {
            return $depth;
        }

        $min = min($featureValues);
        $max = max($featureValues);

        if ($min === $max) {
            return $depth;
        }

        // Random split point
        $splitValue = $min + (mt_rand() / mt_getrandmax()) * ($max - $min);
        $pointValue = $point[$feature] ?? 0;

        // Filter data
        $subData = array_filter($data, function ($d) use ($feature, $splitValue, $pointValue) {
            return ($d[$feature] ?? 0) < $splitValue === $pointValue < $splitValue;
        });

        return $this->isolatePoint($point, $subData, $depth + 1, $maxDepth);
    }

    /**
     * Calculate temporal anomaly (sudden changes).
     */
    private function calculateTemporalAnomaly(array $features, array $history): float
    {
        if (count($history) < 3) {
            return 0;
        }

        // Get recent history
        $recent = array_slice($history, -10);
        $score = 0;

        foreach ($features as $key => $value) {
            if (!is_numeric($value)) {
                continue;
            }

            $recentValues = array_column($recent, $key);
            if (count($recentValues) < 2) {
                continue;
            }

            // Calculate rate of change
            $diffs = [];
            for ($i = 1; $i < count($recentValues); $i++) {
                $diffs[] = abs($recentValues[$i] - $recentValues[$i - 1]);
            }

            $avgDiff = array_sum($diffs) / count($diffs);
            $currentDiff = abs($value - end($recentValues));

            if ($avgDiff > 0 && $currentDiff > $avgDiff * 3) {
                $weight = $this->featureWeights[$key] ?? 0.1;
                $score += ($currentDiff / $avgDiff) * $weight;
            }
        }

        return $score;
    }

    /**
     * Ensemble multiple anomaly scores.
     */
    private function ensembleScore(array $scores): float
    {
        $weights = [
            'zscore' => 0.30,
            'iqr' => 0.25,
            'isolation' => 0.25,
            'temporal' => 0.20,
        ];

        $total = 0;
        $weightSum = 0;

        foreach ($scores as $method => $score) {
            $weight = $weights[$method] ?? 0.25;
            $total += $score * $weight;
            $weightSum += $weight;
        }

        return $weightSum > 0 ? $total / $weightSum : 0;
    }

    /**
     * Identify which features are anomalous.
     */
    private function identifyAnomalousFeatures(array $features, array $history): array
    {
        $anomalous = [];

        foreach ($features as $key => $value) {
            if (!is_numeric($value)) {
                continue;
            }

            $historicalValues = array_column($history, $key);
            if (count($historicalValues) < 5) {
                continue;
            }

            $mean = array_sum($historicalValues) / count($historicalValues);
            $stdDev = sqrt($this->calculateVariance($historicalValues, $mean));

            if ($stdDev > 0) {
                $zScore = abs(($value - $mean) / $stdDev);
                if ($zScore > 2) {
                    $anomalous[$key] = [
                        'value' => $value,
                        'mean' => round($mean, 2),
                        'std_dev' => round($stdDev, 2),
                        'z_score' => round($zScore, 2),
                    ];
                }
            }
        }

        return $anomalous;
    }

    /**
     * Get feature history for entity.
     */
    private function getHistory(string $entityId): array
    {
        return Cache::get($this->cachePrefix . $entityId, []);
    }

    /**
     * Add features to history.
     */
    private function addToHistory(string $entityId, array $features): void
    {
        $history = $this->getHistory($entityId);
        $history[] = array_merge($features, ['timestamp' => time()]);

        // Keep only recent history
        if (count($history) > $this->historySize) {
            $history = array_slice($history, -$this->historySize);
        }

        Cache::put($this->cachePrefix . $entityId, $history, 86400);
    }

    /**
     * Calculate variance.
     */
    private function calculateVariance(array $values, float $mean): float
    {
        $squaredDiffs = array_map(function ($v) use ($mean) {
            return pow($v - $mean, 2);
        }, $values);

        return array_sum($squaredDiffs) / count($squaredDiffs);
    }

    /**
     * Calculate percentile.
     */
    private function percentile(array $data, float $percentile): float
    {
        $index = ($percentile / 100) * (count($data) - 1);
        $lower = floor($index);
        $upper = ceil($index);

        if ($lower === $upper) {
            return $data[(int)$lower];
        }

        return $data[(int)$lower] + ($index - $lower) * ($data[(int)$upper] - $data[(int)$lower]);
    }

    /**
     * Train the model with known normal data.
     */
    public function train(array $normalData, string $entityId): void
    {
        $history = [];
        foreach ($normalData as $features) {
            $history[] = array_merge($features, ['timestamp' => time()]);
        }

        Cache::put($this->cachePrefix . $entityId, $history, 86400 * 7);
    }

    /**
     * Reset model for entity.
     */
    public function reset(string $entityId): void
    {
        Cache::forget($this->cachePrefix . $entityId);
    }
}

/**
 * Result of anomaly detection.
 */
class AnomalyResult
{
    public function __construct(
        public readonly bool $isAnomaly,
        public readonly float $score,
        public readonly string $message,
        public readonly array $methodScores = [],
        public readonly array $anomalousFeatures = []
    ) {}

    public function toArray(): array
    {
        return [
            'is_anomaly' => $this->isAnomaly,
            'score' => round($this->score, 4),
            'message' => $this->message,
            'method_scores' => array_map(fn($s) => round($s, 4), $this->methodScores),
            'anomalous_features' => $this->anomalousFeatures,
        ];
    }
}
