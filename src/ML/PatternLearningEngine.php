<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\ML;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * Pattern Learning Engine.
 *
 * Learns and recognizes patterns from request data:
 * - Sequence pattern detection (Markov chains)
 * - Behavioral clustering
 * - Access pattern modeling
 * - Anomalous sequence detection
 */
class PatternLearningEngine
{
    private array $config;
    private int $sequenceLength;
    private int $minOccurrences;
    private float $confidenceThreshold;
    private string $cachePrefix;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->sequenceLength = $config['sequence_length'] ?? 5;
        $this->minOccurrences = $config['min_occurrences'] ?? 3;
        $this->confidenceThreshold = $config['confidence_threshold'] ?? 0.6;
        $this->cachePrefix = $config['cache_prefix'] ?? 'pattern_learning:';
    }

    /**
     * Learn from a sequence of events.
     */
    public function learn(string $entityId, array $event): void
    {
        $this->recordEvent($entityId, $event);
        $this->updateTransitionMatrix($entityId, $event);
        $this->updateClusterModel($entityId, $event);
    }

    /**
     * Predict next likely event.
     */
    public function predict(string $entityId, ?array $currentEvent = null): PredictionResult
    {
        $transitionMatrix = $this->getTransitionMatrix($entityId);
        $recentSequence = $this->getRecentSequence($entityId);

        if (empty($transitionMatrix) || count($recentSequence) < 2) {
            return new PredictionResult([], 0, 'Insufficient data for prediction');
        }

        $currentState = $this->eventToState($currentEvent ?? end($recentSequence));
        $predictions = [];

        if (isset($transitionMatrix[$currentState])) {
            $total = array_sum($transitionMatrix[$currentState]);
            foreach ($transitionMatrix[$currentState] as $nextState => $count) {
                $probability = $count / $total;
                if ($probability >= 0.1) {
                    $predictions[$nextState] = round($probability, 4);
                }
            }
        }

        arsort($predictions);
        $topPrediction = key($predictions) ?? '';
        $confidence = current($predictions) ?: 0;

        return new PredictionResult(
            array_slice($predictions, 0, 5, true),
            $confidence,
            "Top prediction: {$topPrediction}"
        );
    }

    /**
     * Evaluate how well an event matches learned patterns.
     */
    public function evaluate(string $entityId, array $event): PatternMatchResult
    {
        $transitionMatrix = $this->getTransitionMatrix($entityId);
        $recentSequence = $this->getRecentSequence($entityId);
        $clusterModel = $this->getClusterModel($entityId);

        if (empty($transitionMatrix)) {
            return new PatternMatchResult(true, 1.0, 'No pattern model available');
        }

        $scores = [];

        // Check transition probability
        if (count($recentSequence) >= 1) {
            $prevEvent = end($recentSequence);
            $prevState = $this->eventToState($prevEvent);
            $currentState = $this->eventToState($event);

            if (isset($transitionMatrix[$prevState])) {
                $total = array_sum($transitionMatrix[$prevState]);
                $count = $transitionMatrix[$prevState][$currentState] ?? 0;
                $scores['transition'] = $count / $total;
            } else {
                $scores['transition'] = 0;
            }
        }

        // Check cluster membership
        if (!empty($clusterModel)) {
            $scores['cluster'] = $this->calculateClusterMembership($event, $clusterModel);
        }

        // Check sequence pattern match
        $scores['sequence'] = $this->evaluateSequencePattern($entityId, $event);

        // Aggregate scores
        $avgScore = array_sum($scores) / count($scores);
        $matchesPattern = $avgScore >= $this->confidenceThreshold;

        $anomalies = [];
        if ($scores['transition'] ?? 1 < 0.1) {
            $anomalies[] = 'unusual_transition';
        }
        if ($scores['cluster'] ?? 1 < 0.3) {
            $anomalies[] = 'outside_cluster';
        }
        if ($scores['sequence'] ?? 1 < 0.2) {
            $anomalies[] = 'unusual_sequence';
        }

        return new PatternMatchResult(
            $matchesPattern,
            $avgScore,
            $matchesPattern ? 'Event matches learned patterns' : 'Anomalous event detected',
            $scores,
            $anomalies
        );
    }

    /**
     * Record an event in history.
     */
    private function recordEvent(string $entityId, array $event): void
    {
        $key = $this->cachePrefix . "events:{$entityId}";
        $events = Cache::get($key, []);
        $events[] = array_merge($event, ['_timestamp' => time()]);

        // Keep recent events
        if (count($events) > 1000) {
            $events = array_slice($events, -1000);
        }

        Cache::put($key, $events, 86400 * 7);
    }

    /**
     * Get recent sequence.
     */
    private function getRecentSequence(string $entityId): array
    {
        $key = $this->cachePrefix . "events:{$entityId}";
        $events = Cache::get($key, []);
        return array_slice($events, -$this->sequenceLength);
    }

    /**
     * Update transition probability matrix.
     */
    private function updateTransitionMatrix(string $entityId, array $event): void
    {
        $events = Cache::get($this->cachePrefix . "events:{$entityId}", []);
        if (count($events) < 2) {
            return;
        }

        $key = $this->cachePrefix . "transition:{$entityId}";
        $matrix = Cache::get($key, []);

        // Get previous event
        $prevEvent = $events[count($events) - 2] ?? null;
        if (!$prevEvent) {
            return;
        }

        $prevState = $this->eventToState($prevEvent);
        $currentState = $this->eventToState($event);

        if (!isset($matrix[$prevState])) {
            $matrix[$prevState] = [];
        }

        $matrix[$prevState][$currentState] = ($matrix[$prevState][$currentState] ?? 0) + 1;

        Cache::put($key, $matrix, 86400 * 7);
    }

    /**
     * Get transition matrix.
     */
    private function getTransitionMatrix(string $entityId): array
    {
        return Cache::get($this->cachePrefix . "transition:{$entityId}", []);
    }

    /**
     * Convert event to state string.
     */
    private function eventToState(array $event): string
    {
        // Extract key features for state representation
        $stateFeatures = [
            $event['endpoint'] ?? $event['path'] ?? 'unknown',
            $event['method'] ?? 'GET',
            $event['status_group'] ?? floor(($event['status'] ?? 200) / 100) . 'xx',
        ];

        return implode(':', $stateFeatures);
    }

    /**
     * Update cluster model.
     */
    private function updateClusterModel(string $entityId, array $event): void
    {
        $key = $this->cachePrefix . "cluster:{$entityId}";
        $model = Cache::get($key, ['centroids' => [], 'counts' => []]);

        $features = $this->extractNumericFeatures($event);
        if (empty($features)) {
            return;
        }

        // Find nearest centroid or create new one
        $nearestIdx = $this->findNearestCentroid($features, $model['centroids']);

        if ($nearestIdx === null || $this->calculateDistance($features, $model['centroids'][$nearestIdx]) > 2.0) {
            // Create new centroid
            $model['centroids'][] = $features;
            $model['counts'][] = 1;
        } else {
            // Update existing centroid (running average)
            $count = $model['counts'][$nearestIdx];
            foreach ($features as $key => $value) {
                $model['centroids'][$nearestIdx][$key] =
                    ($model['centroids'][$nearestIdx][$key] * $count + $value) / ($count + 1);
            }
            $model['counts'][$nearestIdx]++;
        }

        // Limit centroids
        if (count($model['centroids']) > 20) {
            $this->mergeClusters($model);
        }

        Cache::put($key, $model, 86400 * 7);
    }

    /**
     * Get cluster model.
     */
    private function getClusterModel(string $entityId): array
    {
        return Cache::get($this->cachePrefix . "cluster:{$entityId}", []);
    }

    /**
     * Extract numeric features from event.
     */
    private function extractNumericFeatures(array $event): array
    {
        $numericKeys = ['response_time', 'payload_size', 'request_size', 'hour', 'day_of_week'];
        $features = [];

        foreach ($numericKeys as $key) {
            if (isset($event[$key]) && is_numeric($event[$key])) {
                $features[$key] = (float)$event[$key];
            }
        }

        // Add derived features
        if (isset($event['timestamp'])) {
            $features['hour'] = (int)date('G', $event['timestamp']);
            $features['day_of_week'] = (int)date('N', $event['timestamp']);
        }

        return $features;
    }

    /**
     * Find nearest centroid.
     */
    private function findNearestCentroid(array $features, array $centroids): ?int
    {
        if (empty($centroids)) {
            return null;
        }

        $minDistance = PHP_FLOAT_MAX;
        $nearestIdx = null;

        foreach ($centroids as $idx => $centroid) {
            $distance = $this->calculateDistance($features, $centroid);
            if ($distance < $minDistance) {
                $minDistance = $distance;
                $nearestIdx = $idx;
            }
        }

        return $nearestIdx;
    }

    /**
     * Calculate Euclidean distance.
     */
    private function calculateDistance(array $a, array $b): float
    {
        $sum = 0;
        $keys = array_unique(array_merge(array_keys($a), array_keys($b)));

        foreach ($keys as $key) {
            $diff = ($a[$key] ?? 0) - ($b[$key] ?? 0);
            $sum += $diff * $diff;
        }

        return sqrt($sum);
    }

    /**
     * Calculate cluster membership score.
     */
    private function calculateClusterMembership(array $event, array $model): float
    {
        $features = $this->extractNumericFeatures($event);
        if (empty($features) || empty($model['centroids'])) {
            return 1.0;
        }

        $nearestIdx = $this->findNearestCentroid($features, $model['centroids']);
        if ($nearestIdx === null) {
            return 0;
        }

        $distance = $this->calculateDistance($features, $model['centroids'][$nearestIdx]);

        // Convert distance to membership score (closer = higher score)
        return exp(-$distance / 2);
    }

    /**
     * Merge closest clusters.
     */
    private function mergeClusters(array &$model): void
    {
        while (count($model['centroids']) > 15) {
            $minDistance = PHP_FLOAT_MAX;
            $mergeI = 0;
            $mergeJ = 1;

            // Find closest pair
            for ($i = 0; $i < count($model['centroids']); $i++) {
                for ($j = $i + 1; $j < count($model['centroids']); $j++) {
                    $distance = $this->calculateDistance($model['centroids'][$i], $model['centroids'][$j]);
                    if ($distance < $minDistance) {
                        $minDistance = $distance;
                        $mergeI = $i;
                        $mergeJ = $j;
                    }
                }
            }

            // Merge
            $countI = $model['counts'][$mergeI];
            $countJ = $model['counts'][$mergeJ];
            $totalCount = $countI + $countJ;

            foreach ($model['centroids'][$mergeI] as $key => $value) {
                $model['centroids'][$mergeI][$key] =
                    ($value * $countI + ($model['centroids'][$mergeJ][$key] ?? 0) * $countJ) / $totalCount;
            }
            $model['counts'][$mergeI] = $totalCount;

            // Remove merged centroid
            array_splice($model['centroids'], $mergeJ, 1);
            array_splice($model['counts'], $mergeJ, 1);
        }
    }

    /**
     * Evaluate sequence pattern.
     */
    private function evaluateSequencePattern(string $entityId, array $event): float
    {
        $events = Cache::get($this->cachePrefix . "events:{$entityId}", []);
        if (count($events) < $this->sequenceLength) {
            return 1.0;
        }

        // Build n-gram model
        $ngrams = [];
        for ($i = 0; $i <= count($events) - $this->sequenceLength; $i++) {
            $sequence = array_slice($events, $i, $this->sequenceLength);
            $key = implode('|', array_map([$this, 'eventToState'], $sequence));
            $ngrams[$key] = ($ngrams[$key] ?? 0) + 1;
        }

        // Check current sequence
        $recentSequence = array_slice($events, -($this->sequenceLength - 1));
        $recentSequence[] = $event;
        $currentKey = implode('|', array_map([$this, 'eventToState'], $recentSequence));

        $total = array_sum($ngrams);
        $occurrences = $ngrams[$currentKey] ?? 0;

        return $total > 0 ? $occurrences / $total : 0;
    }

    /**
     * Get learned patterns summary.
     */
    public function getSummary(string $entityId): array
    {
        $transitionMatrix = $this->getTransitionMatrix($entityId);
        $clusterModel = $this->getClusterModel($entityId);
        $events = Cache::get($this->cachePrefix . "events:{$entityId}", []);

        return [
            'total_events' => count($events),
            'unique_states' => count($transitionMatrix),
            'clusters' => count($clusterModel['centroids'] ?? []),
            'top_transitions' => $this->getTopTransitions($transitionMatrix, 5),
        ];
    }

    /**
     * Get top transitions.
     */
    private function getTopTransitions(array $matrix, int $limit): array
    {
        $transitions = [];

        foreach ($matrix as $from => $tos) {
            foreach ($tos as $to => $count) {
                $transitions["{$from} -> {$to}"] = $count;
            }
        }

        arsort($transitions);
        return array_slice($transitions, 0, $limit, true);
    }

    /**
     * Reset learned patterns.
     */
    public function reset(string $entityId): void
    {
        Cache::forget($this->cachePrefix . "events:{$entityId}");
        Cache::forget($this->cachePrefix . "transition:{$entityId}");
        Cache::forget($this->cachePrefix . "cluster:{$entityId}");
    }
}

/**
 * Prediction result.
 */
class PredictionResult
{
    public function __construct(
        public readonly array $predictions,
        public readonly float $confidence,
        public readonly string $message
    ) {}

    public function toArray(): array
    {
        return [
            'predictions' => $this->predictions,
            'confidence' => $this->confidence,
            'message' => $this->message,
        ];
    }
}

/**
 * Pattern match result.
 */
class PatternMatchResult
{
    public function __construct(
        public readonly bool $matchesPattern,
        public readonly float $score,
        public readonly string $message,
        public readonly array $componentScores = [],
        public readonly array $anomalies = []
    ) {}

    public function toArray(): array
    {
        return [
            'matches_pattern' => $this->matchesPattern,
            'score' => round($this->score, 4),
            'message' => $this->message,
            'component_scores' => $this->componentScores,
            'anomalies' => $this->anomalies,
        ];
    }
}
