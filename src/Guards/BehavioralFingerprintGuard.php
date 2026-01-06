<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardInterface;
use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;
use M9nx\RuntimeGuard\Support\GuardResult;
use Illuminate\Http\Request;

/**
 * Behavioral Fingerprint Guard.
 *
 * Creates and validates behavioral fingerprints based on:
 * - Mouse movement patterns (if JS telemetry available)
 * - Typing cadence and rhythm
 * - Navigation sequence patterns
 * - Request timing signatures
 * - Device/browser consistency
 */
class BehavioralFingerprintGuard implements GuardInterface
{
    private bool $enabled;
    private float $similarityThreshold;
    private int $minDataPoints;
    private bool $trackMousePatterns;
    private bool $trackTypingCadence;
    private bool $trackNavigationSequence;
    private int $fingerprintTtl;
    private ?object $cache;

    public function __construct(array $config = [])
    {
        $this->enabled = $config['enabled'] ?? true;
        $this->similarityThreshold = $config['similarity_threshold'] ?? 0.7;
        $this->minDataPoints = $config['min_data_points'] ?? 5;
        $this->trackMousePatterns = $config['track_mouse_patterns'] ?? false;
        $this->trackTypingCadence = $config['track_typing_cadence'] ?? true;
        $this->trackNavigationSequence = $config['track_navigation_sequence'] ?? true;
        $this->fingerprintTtl = $config['fingerprint_ttl'] ?? 86400;
        $this->cache = $config['cache'] ?? null;
    }

    public function inspect(mixed $input, array $context = []): GuardResultInterface
    {
        if (!$this->enabled) {
            return GuardResult::pass($this->getName());
        }

        // Get request from context or input
        $request = $context['request'] ?? ($input instanceof Request ? $input : app('request'));
        $threats = [];
        $metadata = [];

        // Extract behavioral data from request
        $behaviorData = $this->extractBehaviorData($request);
        $metadata['behavior_data_present'] = !empty($behaviorData);

        if (empty($behaviorData)) {
            return new GuardResult(
                guardName: $this->getName(),
                passed: true,
                message: 'No behavior data to analyze',
                metadata: $metadata
            );
        }

        // Get stored fingerprint for this session/user
        $sessionId = $request->session()?->getId() ?? $this->generateSessionKey($request);
        $storedFingerprint = $this->getStoredFingerprint($sessionId);

        if ($storedFingerprint) {
            // Compare behavioral patterns
            $similarity = $this->calculateSimilarity($behaviorData, $storedFingerprint);
            $metadata['similarity_score'] = $similarity;

            if ($similarity < $this->similarityThreshold) {
                $threats[] = [
                    'type' => 'behavioral_anomaly',
                    'severity' => 'high',
                    'message' => 'Behavioral fingerprint mismatch detected',
                    'details' => [
                        'similarity' => $similarity,
                        'threshold' => $this->similarityThreshold,
                        'anomalies' => $this->identifyAnomalies($behaviorData, $storedFingerprint),
                    ],
                ];
            }
        }

        // Update fingerprint with new data
        $this->updateFingerprint($sessionId, $behaviorData);

        // Check for bot-like behavior patterns
        $botIndicators = $this->detectBotPatterns($behaviorData);
        if (!empty($botIndicators)) {
            $threats[] = [
                'type' => 'bot_behavior_pattern',
                'severity' => 'medium',
                'message' => 'Bot-like behavioral patterns detected',
                'details' => ['indicators' => $botIndicators],
            ];
        }

        if (!empty($threats)) {
            return GuardResult::fail(
                $this->getName(),
                $this->getHighestSeverity($threats),
                'Behavioral fingerprint anomaly detected',
                ['threats' => $threats, ...$metadata]
            );
        }

        return new GuardResult(
            guardName: $this->getName(),
            passed: true,
            message: 'No behavioral anomaly detected',
            metadata: $metadata
        );
    }

    /**
     * Determine the highest severity from threats.
     */
    private function getHighestSeverity(array $threats): ThreatLevel
    {
        $severityOrder = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        $highest = 0;

        foreach ($threats as $threat) {
            $severity = $threat['severity'] ?? 'low';
            $highest = max($highest, $severityOrder[$severity] ?? 1);
        }

        return match ($highest) {
            4 => ThreatLevel::CRITICAL,
            3 => ThreatLevel::HIGH,
            2 => ThreatLevel::MEDIUM,
            default => ThreatLevel::LOW,
        };
    }

    /**
     * Extract behavioral data from request.
     */
    private function extractBehaviorData(object $request): array
    {
        $data = [];

        // Timing data
        $data['request_time'] = microtime(true);
        $data['time_since_last'] = $this->getTimeSinceLastRequest($request);

        // Navigation sequence
        if ($this->trackNavigationSequence) {
            $data['path'] = $request->path();
            $data['method'] = $request->method();
            $data['referer'] = $request->header('Referer');
        }

        // Client-side telemetry (if provided via headers/body)
        $telemetry = $request->header('X-Behavior-Telemetry');
        if ($telemetry) {
            $decoded = json_decode(base64_decode($telemetry), true);
            if ($decoded) {
                if ($this->trackMousePatterns && isset($decoded['mouse'])) {
                    $data['mouse_patterns'] = $this->normalizeMouseData($decoded['mouse']);
                }
                if ($this->trackTypingCadence && isset($decoded['typing'])) {
                    $data['typing_cadence'] = $this->normalizeTypingData($decoded['typing']);
                }
            }
        }

        // Request characteristics
        $data['input_size'] = strlen($request->getContent() ?? '');
        $data['param_count'] = count($request->all());
        $data['header_count'] = count($request->headers->all());

        return $data;
    }

    /**
     * Calculate similarity between current behavior and stored fingerprint.
     */
    private function calculateSimilarity(array $current, array $stored): float
    {
        $scores = [];
        $weights = [
            'timing_pattern' => 0.3,
            'navigation_sequence' => 0.25,
            'typing_cadence' => 0.25,
            'request_characteristics' => 0.2,
        ];

        // Timing pattern similarity
        if (isset($stored['timing_intervals']) && count($stored['timing_intervals']) >= $this->minDataPoints) {
            $currentInterval = $current['time_since_last'] ?? 0;
            $avgInterval = array_sum($stored['timing_intervals']) / count($stored['timing_intervals']);
            $stdDev = $this->standardDeviation($stored['timing_intervals']);
            
            if ($stdDev > 0) {
                $zScore = abs($currentInterval - $avgInterval) / $stdDev;
                $scores['timing_pattern'] = max(0, 1 - ($zScore / 3));
            } else {
                $scores['timing_pattern'] = $currentInterval === $avgInterval ? 1.0 : 0.5;
            }
        }

        // Navigation sequence similarity
        if ($this->trackNavigationSequence && isset($stored['navigation_history'])) {
            $scores['navigation_sequence'] = $this->calculateNavigationSimilarity(
                $current,
                $stored['navigation_history']
            );
        }

        // Typing cadence similarity
        if ($this->trackTypingCadence && isset($current['typing_cadence']) && isset($stored['typing_profile'])) {
            $scores['typing_cadence'] = $this->calculateTypingSimilarity(
                $current['typing_cadence'],
                $stored['typing_profile']
            );
        }

        // Request characteristics similarity
        if (isset($stored['request_profile'])) {
            $scores['request_characteristics'] = $this->calculateRequestSimilarity($current, $stored['request_profile']);
        }

        // Weighted average
        $totalWeight = 0;
        $weightedSum = 0;
        foreach ($scores as $key => $score) {
            $weight = $weights[$key] ?? 0.25;
            $weightedSum += $score * $weight;
            $totalWeight += $weight;
        }

        return $totalWeight > 0 ? $weightedSum / $totalWeight : 0.5;
    }

    /**
     * Identify specific anomalies.
     */
    private function identifyAnomalies(array $current, array $stored): array
    {
        $anomalies = [];

        // Check timing anomaly
        if (isset($stored['timing_intervals']) && isset($current['time_since_last'])) {
            $avgInterval = array_sum($stored['timing_intervals']) / count($stored['timing_intervals']);
            if ($current['time_since_last'] < $avgInterval * 0.1) {
                $anomalies[] = 'unusually_fast_requests';
            }
        }

        // Check navigation anomaly
        if (isset($stored['common_paths']) && isset($current['path'])) {
            if (!in_array($current['path'], $stored['common_paths'])) {
                $anomalies[] = 'unusual_navigation_path';
            }
        }

        return $anomalies;
    }

    /**
     * Detect bot-like patterns.
     */
    private function detectBotPatterns(array $behaviorData): array
    {
        $indicators = [];

        // Perfect timing intervals (bots often have consistent timing)
        if (isset($behaviorData['time_since_last'])) {
            $interval = $behaviorData['time_since_last'];
            // Suspiciously round numbers
            if ($interval > 0 && fmod($interval, 1.0) === 0.0) {
                $indicators[] = 'perfectly_round_timing';
            }
        }

        // Missing human-like variations in typing
        if (isset($behaviorData['typing_cadence'])) {
            $cadence = $behaviorData['typing_cadence'];
            if (isset($cadence['variance']) && $cadence['variance'] < 0.01) {
                $indicators[] = 'robotic_typing_pattern';
            }
        }

        return $indicators;
    }

    /**
     * Get stored fingerprint.
     */
    private function getStoredFingerprint(string $sessionId): ?array
    {
        if (!$this->cache) {
            return null;
        }

        return $this->cache->get("behavior_fp:{$sessionId}");
    }

    /**
     * Update stored fingerprint.
     */
    private function updateFingerprint(string $sessionId, array $newData): void
    {
        if (!$this->cache) {
            return;
        }

        $existing = $this->getStoredFingerprint($sessionId) ?? [
            'timing_intervals' => [],
            'navigation_history' => [],
            'typing_profile' => null,
            'request_profile' => [],
            'common_paths' => [],
        ];

        // Update timing intervals
        if (isset($newData['time_since_last']) && $newData['time_since_last'] > 0) {
            $existing['timing_intervals'][] = $newData['time_since_last'];
            $existing['timing_intervals'] = array_slice($existing['timing_intervals'], -50);
        }

        // Update navigation history
        if (isset($newData['path'])) {
            $existing['navigation_history'][] = [
                'path' => $newData['path'],
                'method' => $newData['method'] ?? 'GET',
                'time' => $newData['request_time'],
            ];
            $existing['navigation_history'] = array_slice($existing['navigation_history'], -100);

            // Update common paths
            $pathCounts = array_count_values(array_column($existing['navigation_history'], 'path'));
            arsort($pathCounts);
            $existing['common_paths'] = array_slice(array_keys($pathCounts), 0, 20);
        }

        // Update request profile
        $existing['request_profile'] = [
            'avg_input_size' => $this->runningAverage(
                $existing['request_profile']['avg_input_size'] ?? 0,
                $newData['input_size'] ?? 0,
                count($existing['timing_intervals'])
            ),
            'avg_param_count' => $this->runningAverage(
                $existing['request_profile']['avg_param_count'] ?? 0,
                $newData['param_count'] ?? 0,
                count($existing['timing_intervals'])
            ),
        ];

        $this->cache->put("behavior_fp:{$sessionId}", $existing, $this->fingerprintTtl);
    }

    /**
     * Calculate running average.
     */
    private function runningAverage(float $currentAvg, float $newValue, int $count): float
    {
        if ($count <= 1) {
            return $newValue;
        }
        return (($currentAvg * ($count - 1)) + $newValue) / $count;
    }

    /**
     * Standard deviation.
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

    private function getTimeSinceLastRequest(object $request): float
    {
        // Implementation depends on session/cache tracking
        return 0;
    }

    private function generateSessionKey(object $request): string
    {
        return hash('sha256', $request->ip() . $request->userAgent());
    }

    private function normalizeMouseData(array $data): array
    {
        return $data; // Normalize mouse movement data
    }

    private function normalizeTypingData(array $data): array
    {
        return $data; // Normalize typing cadence data
    }

    private function calculateNavigationSimilarity(array $current, array $history): float
    {
        return 0.8; // Placeholder
    }

    private function calculateTypingSimilarity(array $current, ?array $profile): float
    {
        return 0.8; // Placeholder
    }

    private function calculateRequestSimilarity(array $current, array $profile): float
    {
        return 0.8; // Placeholder
    }

    public function getName(): string
    {
        return 'behavioral_fingerprint';
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getPriority(): int
    {
        return 40;
    }

    public function getSeverity(): string
    {
        return 'high';
    }
}
