<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Guards;

use Mounir\RuntimeGuard\Contracts\GuardInterface;
use Mounir\RuntimeGuard\Context\RuntimeContext;
use Mounir\RuntimeGuard\Results\GuardResult;

/**
 * Timing Attack Shield Guard.
 *
 * Detects and prevents timing attacks:
 * - Enforces constant-time comparisons
 * - Adds response time jitter
 * - Detects timing probing patterns
 * - Monitors response time anomalies
 */
class TimingShieldGuard implements GuardInterface
{
    private bool $enabled;
    private bool $addResponseJitter;
    private int $minJitterMs;
    private int $maxJitterMs;
    private bool $detectTimingProbes;
    private int $probeDetectionWindow;
    private int $probeThreshold;
    private bool $enforceConstantTime;
    private int $targetResponseTimeMs;
    private ?object $cache;
    private array $sensitiveEndpoints;

    public function __construct(array $config = [])
    {
        $this->enabled = $config['enabled'] ?? true;
        $this->addResponseJitter = $config['add_response_jitter'] ?? true;
        $this->minJitterMs = $config['min_jitter_ms'] ?? 5;
        $this->maxJitterMs = $config['max_jitter_ms'] ?? 50;
        $this->detectTimingProbes = $config['detect_timing_probes'] ?? true;
        $this->probeDetectionWindow = $config['probe_detection_window'] ?? 60;
        $this->probeThreshold = $config['probe_threshold'] ?? 20;
        $this->enforceConstantTime = $config['enforce_constant_time'] ?? false;
        $this->targetResponseTimeMs = $config['target_response_time_ms'] ?? 200;
        $this->cache = $config['cache'] ?? null;
        $this->sensitiveEndpoints = $config['sensitive_endpoints'] ?? [
            '/api/login',
            '/api/auth',
            '/api/verify',
            '/api/password',
            '/api/token',
            '/api/otp',
            '/api/mfa',
        ];
    }

    public function inspect(RuntimeContext $context): GuardResult
    {
        if (!$this->enabled) {
            return GuardResult::pass($this->getName());
        }

        $request = $context->getRequest();
        $threats = [];
        $metadata = [];

        $path = '/' . ltrim($request->path(), '/');
        $isSensitive = $this->isSensitiveEndpoint($path);
        $metadata['is_sensitive_endpoint'] = $isSensitive;

        // Check 1: Detect timing probe patterns
        if ($this->detectTimingProbes && $isSensitive) {
            $probeResult = $this->detectProbePattern($request, $path);
            if ($probeResult['detected']) {
                $threats[] = $probeResult['threat'];
            }
            $metadata['probe_detection'] = $probeResult;
        }

        // Register callback for response jitter
        if ($this->addResponseJitter && $isSensitive) {
            $jitter = $this->calculateJitter();
            $metadata['jitter_ms'] = $jitter;
            $context->setMetadata('timing_jitter_ms', $jitter);
        }

        // Store request timing for analysis
        if ($this->cache && $isSensitive) {
            $this->recordRequestTiming($request, $path);
        }

        if (!empty($threats)) {
            return GuardResult::fail($this->getName(), $threats)
                ->withMetadata($metadata);
        }

        return GuardResult::pass($this->getName())
            ->withMetadata($metadata);
    }

    /**
     * Check if endpoint is sensitive to timing attacks.
     */
    private function isSensitiveEndpoint(string $path): bool
    {
        foreach ($this->sensitiveEndpoints as $pattern) {
            if (str_starts_with($path, $pattern)) {
                return true;
            }

            // Support wildcards
            $regex = '/^' . str_replace(['\*', '\?'], ['.*', '.'], preg_quote($pattern, '/')) . '/';
            if (preg_match($regex, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect timing probe patterns.
     */
    private function detectProbePattern(object $request, string $path): array
    {
        if (!$this->cache) {
            return ['detected' => false];
        }

        $ip = $request->ip();
        $key = "timing_probe:{$ip}:{$path}";
        $history = $this->cache->get($key, []);

        $now = microtime(true);
        
        // Clean old entries
        $history = array_filter($history, fn($t) => $t > $now - $this->probeDetectionWindow);
        $history[] = $now;
        $this->cache->put($key, $history, $this->probeDetectionWindow);

        $requestCount = count($history);

        // Check for probe threshold
        if ($requestCount >= $this->probeThreshold) {
            // Calculate timing variance
            $intervals = [];
            $sorted = array_values($history);
            for ($i = 1; $i < count($sorted); $i++) {
                $intervals[] = $sorted[$i] - $sorted[$i - 1];
            }

            $variance = $this->calculateVariance($intervals);
            $meanInterval = array_sum($intervals) / count($intervals);

            // Low variance with high frequency = systematic probing
            $isProbing = $variance < 0.01 && $meanInterval < 1.0;

            if ($isProbing) {
                return [
                    'detected' => true,
                    'request_count' => $requestCount,
                    'mean_interval' => round($meanInterval * 1000, 2),
                    'variance' => $variance,
                    'threat' => [
                        'type' => 'timing_probe_detected',
                        'severity' => 'high',
                        'message' => 'Systematic timing probe pattern detected',
                        'details' => [
                            'requests_in_window' => $requestCount,
                            'mean_interval_ms' => round($meanInterval * 1000, 2),
                            'endpoint' => $path,
                        ],
                    ],
                ];
            }
        }

        return [
            'detected' => false,
            'request_count' => $requestCount,
        ];
    }

    /**
     * Calculate variance of values.
     */
    private function calculateVariance(array $values): float
    {
        if (count($values) < 2) {
            return 0;
        }

        $mean = array_sum($values) / count($values);
        $squaredDiffs = array_map(fn($x) => pow($x - $mean, 2), $values);

        return array_sum($squaredDiffs) / count($values);
    }

    /**
     * Calculate jitter to add to response.
     */
    private function calculateJitter(): int
    {
        return random_int($this->minJitterMs, $this->maxJitterMs);
    }

    /**
     * Record request timing for analysis.
     */
    private function recordRequestTiming(object $request, string $path): void
    {
        if (!$this->cache) {
            return;
        }

        $ip = $request->ip();
        $key = "timing_history:{$ip}:{$path}";
        $history = $this->cache->get($key, []);

        $history[] = [
            'time' => microtime(true),
            'request_start' => defined('LARAVEL_START') ? LARAVEL_START : microtime(true),
        ];

        // Keep last 100 entries
        $history = array_slice($history, -100);
        $this->cache->put($key, $history, 3600);
    }

    /**
     * Apply response jitter.
     * Should be called before sending response.
     */
    public function applyJitter(int $jitterMs): void
    {
        if ($jitterMs > 0) {
            usleep($jitterMs * 1000);
        }
    }

    /**
     * Enforce constant response time.
     * Should be called before sending response.
     */
    public function enforceConstantTime(float $startTime): void
    {
        if (!$this->enforceConstantTime) {
            return;
        }

        $elapsed = (microtime(true) - $startTime) * 1000; // ms
        $remaining = $this->targetResponseTimeMs - $elapsed;

        if ($remaining > 0) {
            usleep((int) ($remaining * 1000));
        }
    }

    /**
     * Constant-time string comparison.
     */
    public static function constantTimeCompare(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }

    /**
     * Constant-time array key lookup.
     * Prevents timing attacks on array key existence checks.
     */
    public static function constantTimeLookup(array $haystack, string $needle, $default = null)
    {
        $found = $default;
        $targetHash = hash('sha256', $needle);

        foreach ($haystack as $key => $value) {
            $keyHash = hash('sha256', (string) $key);
            if (hash_equals($targetHash, $keyHash)) {
                $found = $value;
            }
        }

        return $found;
    }

    /**
     * Constant-time conditional selection.
     * Returns $a if $condition is true, $b otherwise.
     * Timing should not reveal which branch was taken.
     */
    public static function constantTimeSelect(bool $condition, $a, $b)
    {
        // Both values are evaluated
        $mask = $condition ? -1 : 0;
        
        if (is_int($a) && is_int($b)) {
            return ($a & $mask) | ($b & ~$mask);
        }

        // For non-integers, we can't do bit manipulation
        // but we still evaluate both and select
        $result = $condition ? $a : $b;
        
        // Touch both values to prevent optimization
        $_ = $a . $b;

        return $result;
    }

    /**
     * Get timing attack risk assessment for endpoint.
     */
    public function assessEndpointRisk(string $endpoint): array
    {
        $risk = 'low';
        $factors = [];

        // Check if it's in sensitive list
        if ($this->isSensitiveEndpoint($endpoint)) {
            $risk = 'high';
            $factors[] = 'sensitive_endpoint';
        }

        // Authentication-related
        $authKeywords = ['login', 'auth', 'password', 'token', 'verify', 'otp', 'mfa', '2fa'];
        foreach ($authKeywords as $keyword) {
            if (str_contains(strtolower($endpoint), $keyword)) {
                $risk = 'high';
                $factors[] = "contains_keyword:{$keyword}";
                break;
            }
        }

        // API key or secret related
        $secretKeywords = ['key', 'secret', 'api-key', 'apikey'];
        foreach ($secretKeywords as $keyword) {
            if (str_contains(strtolower($endpoint), $keyword)) {
                $risk = 'medium';
                $factors[] = "contains_keyword:{$keyword}";
            }
        }

        return [
            'endpoint' => $endpoint,
            'risk' => $risk,
            'factors' => $factors,
            'recommendations' => $this->getRecommendations($risk),
        ];
    }

    /**
     * Get recommendations based on risk level.
     */
    private function getRecommendations(string $risk): array
    {
        return match ($risk) {
            'high' => [
                'Use constant-time string comparison (hash_equals)',
                'Add response time jitter',
                'Consider enforcing constant response times',
                'Monitor for timing probe patterns',
                'Implement rate limiting',
            ],
            'medium' => [
                'Use constant-time string comparison for secrets',
                'Consider adding response jitter',
                'Monitor unusual request patterns',
            ],
            default => [
                'Standard security practices',
                'Use hash_equals for secret comparisons',
            ],
        };
    }

    /**
     * Get statistics about timing attack detection.
     */
    public function getStats(): array
    {
        return [
            'enabled' => $this->enabled,
            'jitter_enabled' => $this->addResponseJitter,
            'jitter_range' => [$this->minJitterMs, $this->maxJitterMs],
            'probe_detection' => $this->detectTimingProbes,
            'probe_threshold' => $this->probeThreshold,
            'constant_time_enforced' => $this->enforceConstantTime,
            'target_response_time_ms' => $this->targetResponseTimeMs,
            'sensitive_endpoints_count' => count($this->sensitiveEndpoints),
        ];
    }

    public function getName(): string
    {
        return 'timing_shield';
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getPriority(): int
    {
        return 95; // Run very early
    }

    public function getSeverity(): string
    {
        return 'high';
    }
}
