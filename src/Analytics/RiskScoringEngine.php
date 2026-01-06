<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Analytics;

/**
 * Dynamic risk scoring engine with adaptive thresholds.
 *
 * Calculates risk scores based on:
 * - Guard violations
 * - Attack patterns
 * - Historical behavior
 * - Contextual factors
 */
class RiskScoringEngine
{
    // Risk level thresholds
    public const RISK_CRITICAL = 90;
    public const RISK_HIGH = 70;
    public const RISK_MEDIUM = 40;
    public const RISK_LOW = 20;

    private array $config;
    private array $factorWeights;
    private array $guardSeverities;
    private array $entityHistory = [];

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'base_score' => 0,
            'decay_rate' => 0.1, // Score decay per hour
            'max_history' => 100,
            'adaptive_threshold' => true,
            'baseline_period' => 3600, // 1 hour
        ], $config);

        $this->factorWeights = $config['factor_weights'] ?? [
            'guard_violation' => 20,
            'repeated_violation' => 30,
            'velocity_anomaly' => 25,
            'geo_anomaly' => 15,
            'pattern_match' => 35,
            'time_anomaly' => 10,
            'fingerprint_change' => 20,
            'known_bad_actor' => 50,
        ];

        $this->guardSeverities = $config['guard_severities'] ?? [
            'sql_injection' => 1.0,
            'command_injection' => 1.0,
            'deserialization' => 0.9,
            'file_operation' => 0.8,
            'xss' => 0.7,
            'ssrf' => 0.8,
            'credential_stuffing' => 0.9,
            'mass_assignment' => 0.6,
            'nosql' => 0.8,
            'graphql' => 0.6,
            'session_integrity' => 0.7,
            'anomaly' => 0.5,
        ];
    }

    /**
     * Calculate risk score for an entity.
     */
    public function calculateScore(string $entityId, array $context = []): RiskScore
    {
        $factors = [];
        $baseScore = $this->config['base_score'];

        // Factor 1: Current violations
        if (isset($context['violation'])) {
            $factors['current_violation'] = $this->scoreViolation($context['violation']);
        }

        // Factor 2: Historical violations
        $historyScore = $this->scoreHistory($entityId);
        if ($historyScore > 0) {
            $factors['history'] = $historyScore;
        }

        // Factor 3: Velocity (request rate)
        if (isset($context['request_rate'])) {
            $factors['velocity'] = $this->scoreVelocity($context['request_rate']);
        }

        // Factor 4: Geographic anomaly
        if (isset($context['geo_data'])) {
            $geoScore = $this->scoreGeoAnomaly($entityId, $context['geo_data']);
            if ($geoScore > 0) {
                $factors['geo_anomaly'] = $geoScore;
            }
        }

        // Factor 5: Pattern matching
        if (isset($context['patterns'])) {
            $factors['pattern_match'] = $this->scorePatterns($context['patterns']);
        }

        // Factor 6: Time-based anomaly
        if (isset($context['timestamp'])) {
            $timeScore = $this->scoreTimeAnomaly($entityId, $context['timestamp']);
            if ($timeScore > 0) {
                $factors['time_anomaly'] = $timeScore;
            }
        }

        // Factor 7: Known bad actor
        if (!empty($context['known_bad_actor'])) {
            $factors['known_bad_actor'] = $this->factorWeights['known_bad_actor'];
        }

        // Factor 8: Fingerprint change
        if (isset($context['fingerprint_changed']) && $context['fingerprint_changed']) {
            $factors['fingerprint_change'] = $this->factorWeights['fingerprint_change'];
        }

        // Calculate total score
        $totalScore = $baseScore + array_sum($factors);

        // Apply decay from last score
        $lastScore = $this->getLastScore($entityId);
        if ($lastScore) {
            $hoursSinceUpdate = (time() - $lastScore['timestamp']) / 3600;
            $decayedPrevious = max(0, $lastScore['score'] - ($this->config['decay_rate'] * $hoursSinceUpdate * $lastScore['score']));
            $totalScore = max($totalScore, $decayedPrevious * 0.8 + $totalScore * 0.2);
        }

        // Clamp to 0-100
        $totalScore = max(0, min(100, $totalScore));

        $riskScore = new RiskScore(
            score: $totalScore,
            level: $this->determineLevel($totalScore),
            factors: $factors,
            entityId: $entityId,
            timestamp: time()
        );

        // Store for history
        $this->recordScore($entityId, $riskScore);

        return $riskScore;
    }

    /**
     * Score a violation.
     */
    private function scoreViolation(array $violation): float
    {
        $guardName = strtolower($violation['guard'] ?? 'unknown');
        $severity = $this->guardSeverities[$guardName] ?? 0.5;

        $baseWeight = $this->factorWeights['guard_violation'];

        return $baseWeight * $severity;
    }

    /**
     * Score historical behavior.
     */
    private function scoreHistory(string $entityId): float
    {
        $history = $this->entityHistory[$entityId] ?? [];

        if (empty($history)) {
            return 0;
        }

        // Count violations in the baseline period
        $cutoff = time() - $this->config['baseline_period'];
        $recentViolations = 0;
        $totalSeverity = 0;

        foreach ($history as $entry) {
            if ($entry['timestamp'] >= $cutoff) {
                $recentViolations++;
                $totalSeverity += $entry['score'] ?? 0;
            }
        }

        if ($recentViolations <= 1) {
            return 0;
        }

        // Repeated violations increase score exponentially
        return min(
            $this->factorWeights['repeated_violation'],
            $this->factorWeights['repeated_violation'] * log($recentViolations + 1)
        );
    }

    /**
     * Score velocity anomaly.
     */
    private function scoreVelocity(float $requestRate): float
    {
        // Normal rate: 1-10 requests/minute
        // Suspicious: 10-50 requests/minute
        // Attacking: 50+ requests/minute
        if ($requestRate <= 10) {
            return 0;
        }

        if ($requestRate <= 50) {
            return $this->factorWeights['velocity_anomaly'] * (($requestRate - 10) / 40);
        }

        return $this->factorWeights['velocity_anomaly'];
    }

    /**
     * Score geographic anomaly.
     */
    private function scoreGeoAnomaly(string $entityId, array $geoData): float
    {
        $history = $this->entityHistory[$entityId] ?? [];

        if (empty($history)) {
            return 0;
        }

        // Check for impossible travel
        $lastGeo = null;
        foreach (array_reverse($history) as $entry) {
            if (isset($entry['geo'])) {
                $lastGeo = $entry['geo'];
                break;
            }
        }

        if (!$lastGeo) {
            return 0;
        }

        // Different country = suspicious
        if (($geoData['country'] ?? '') !== ($lastGeo['country'] ?? '')) {
            return $this->factorWeights['geo_anomaly'];
        }

        return 0;
    }

    /**
     * Score pattern matches.
     */
    private function scorePatterns(array $patterns): float
    {
        if (empty($patterns)) {
            return 0;
        }

        $score = 0;
        foreach ($patterns as $pattern) {
            $patternSeverity = $pattern['severity'] ?? 0.5;
            $score += $this->factorWeights['pattern_match'] * $patternSeverity;
        }

        return min($score, $this->factorWeights['pattern_match'] * 2);
    }

    /**
     * Score time-based anomaly.
     */
    private function scoreTimeAnomaly(string $entityId, int $timestamp): float
    {
        $hour = (int) date('G', $timestamp);

        // Suspicious hours (2 AM - 5 AM local time)
        if ($hour >= 2 && $hour <= 5) {
            return $this->factorWeights['time_anomaly'];
        }

        return 0;
    }

    /**
     * Determine risk level from score.
     */
    private function determineLevel(float $score): string
    {
        if ($score >= self::RISK_CRITICAL) {
            return 'critical';
        }

        if ($score >= self::RISK_HIGH) {
            return 'high';
        }

        if ($score >= self::RISK_MEDIUM) {
            return 'medium';
        }

        if ($score >= self::RISK_LOW) {
            return 'low';
        }

        return 'minimal';
    }

    /**
     * Get last recorded score for entity.
     */
    private function getLastScore(string $entityId): ?array
    {
        $history = $this->entityHistory[$entityId] ?? [];

        return end($history) ?: null;
    }

    /**
     * Record a score for an entity.
     */
    private function recordScore(string $entityId, RiskScore $score): void
    {
        if (!isset($this->entityHistory[$entityId])) {
            $this->entityHistory[$entityId] = [];
        }

        $this->entityHistory[$entityId][] = [
            'score' => $score->score,
            'level' => $score->level,
            'timestamp' => $score->timestamp,
        ];

        // Trim history
        if (count($this->entityHistory[$entityId]) > $this->config['max_history']) {
            $this->entityHistory[$entityId] = array_slice(
                $this->entityHistory[$entityId],
                -$this->config['max_history']
            );
        }
    }

    /**
     * Get entity history.
     */
    public function getHistory(string $entityId): array
    {
        return $this->entityHistory[$entityId] ?? [];
    }

    /**
     * Clear entity history.
     */
    public function clearHistory(string $entityId): void
    {
        unset($this->entityHistory[$entityId]);
    }

    /**
     * Get adaptive threshold based on system state.
     */
    public function getAdaptiveThreshold(string $level): float
    {
        if (!$this->config['adaptive_threshold']) {
            return match ($level) {
                'critical' => self::RISK_CRITICAL,
                'high' => self::RISK_HIGH,
                'medium' => self::RISK_MEDIUM,
                'low' => self::RISK_LOW,
                default => 0,
            };
        }

        // Calculate system-wide average
        $allScores = [];
        foreach ($this->entityHistory as $history) {
            foreach ($history as $entry) {
                $allScores[] = $entry['score'] ?? 0;
            }
        }

        if (empty($allScores)) {
            return match ($level) {
                'critical' => self::RISK_CRITICAL,
                'high' => self::RISK_HIGH,
                'medium' => self::RISK_MEDIUM,
                'low' => self::RISK_LOW,
                default => 0,
            };
        }

        $average = array_sum($allScores) / count($allScores);
        $stdDev = $this->standardDeviation($allScores);

        // Adjust thresholds based on standard deviation
        return match ($level) {
            'critical' => max(80, self::RISK_CRITICAL - $stdDev * 0.1),
            'high' => max(60, self::RISK_HIGH - $stdDev * 0.1),
            'medium' => max(30, self::RISK_MEDIUM - $stdDev * 0.1),
            'low' => max(10, self::RISK_LOW - $stdDev * 0.1),
            default => 0,
        };
    }

    /**
     * Calculate standard deviation.
     */
    private function standardDeviation(array $values): float
    {
        $count = count($values);
        if ($count < 2) {
            return 0;
        }

        $mean = array_sum($values) / $count;
        $squaredDiffs = array_map(fn($x) => pow($x - $mean, 2), $values);

        return sqrt(array_sum($squaredDiffs) / ($count - 1));
    }

    /**
     * Bulk calculate scores.
     */
    public function bulkCalculate(array $entities): array
    {
        $results = [];
        foreach ($entities as $entityId => $context) {
            $results[$entityId] = $this->calculateScore($entityId, $context);
        }

        return $results;
    }

    /**
     * Get high-risk entities.
     */
    public function getHighRiskEntities(float $threshold = null): array
    {
        $threshold = $threshold ?? self::RISK_HIGH;
        $highRisk = [];

        foreach ($this->entityHistory as $entityId => $history) {
            $lastEntry = end($history);
            if ($lastEntry && ($lastEntry['score'] ?? 0) >= $threshold) {
                $highRisk[$entityId] = $lastEntry;
            }
        }

        arsort($highRisk);

        return $highRisk;
    }

    /**
     * Export scores for analysis.
     */
    public function export(): array
    {
        return [
            'config' => $this->config,
            'factor_weights' => $this->factorWeights,
            'guard_severities' => $this->guardSeverities,
            'entity_count' => count($this->entityHistory),
            'high_risk_count' => count($this->getHighRiskEntities()),
        ];
    }
}

/**
 * Risk score value object.
 */
class RiskScore implements \JsonSerializable
{
    public function __construct(
        public readonly float $score,
        public readonly string $level,
        public readonly array $factors,
        public readonly string $entityId,
        public readonly int $timestamp
    ) {}

    public function isCritical(): bool
    {
        return $this->level === 'critical';
    }

    public function isHigh(): bool
    {
        return $this->level === 'high' || $this->level === 'critical';
    }

    public function shouldBlock(): bool
    {
        return $this->score >= RiskScoringEngine::RISK_HIGH;
    }

    public function shouldChallenge(): bool
    {
        return $this->score >= RiskScoringEngine::RISK_MEDIUM && $this->score < RiskScoringEngine::RISK_HIGH;
    }

    public function shouldMonitor(): bool
    {
        return $this->score >= RiskScoringEngine::RISK_LOW;
    }

    public function jsonSerialize(): array
    {
        return [
            'score' => $this->score,
            'level' => $this->level,
            'factors' => $this->factors,
            'entity_id' => $this->entityId,
            'timestamp' => $this->timestamp,
            'actions' => [
                'should_block' => $this->shouldBlock(),
                'should_challenge' => $this->shouldChallenge(),
                'should_monitor' => $this->shouldMonitor(),
            ],
        ];
    }
}
