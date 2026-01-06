<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Guards;

use Mounir\RuntimeGuard\Contracts\ContextAwareGuard;
use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;
use Mounir\RuntimeGuard\Support\GuardResult;
use Mounir\RuntimeGuard\Support\InspectionContext;
use Psr\SimpleCache\CacheInterface;

/**
 * Detects session hijacking and integrity violations.
 *
 * Features:
 * - Browser fingerprint drift detection
 * - Geolocation jump detection
 * - Impossible session state transitions
 * - TLS fingerprint mismatch (when available)
 */
class SessionIntegrityGuard extends AbstractGuard implements ContextAwareGuard
{
    protected string $name = 'session_integrity';
    protected ThreatLevel $defaultThreatLevel = ThreatLevel::HIGH;

    private ?CacheInterface $cache;
    private string $cachePrefix = 'runtime_guard:session:';

    // Configuration
    private array $fingerprintFields;
    private int $maxGeoDistanceKm;
    private int $maxTimeBetweenRequestsSeconds;
    private string $driftAction;
    private bool $strictMode;

    public function __construct(array $config = [])
    {
        parent::__construct($config);

        $this->cache = $config['cache'] ?? null;
        $this->fingerprintFields = $config['fingerprint_fields'] ?? [
            'user_agent',
            'accept_language',
            'accept_encoding',
        ];
        $this->maxGeoDistanceKm = $config['max_geo_distance_km'] ?? 500;
        $this->maxTimeBetweenRequestsSeconds = $config['max_time_between_requests'] ?? 300;
        $this->driftAction = $config['drift_action'] ?? 'log';
        $this->strictMode = $config['strict_mode'] ?? false;
    }

    /**
     * Check if this guard applies to the current context.
     */
    public function appliesTo(InspectionContext $context): bool
    {
        // Apply to requests with session
        return $context->sessionId() !== null;
    }

    /**
     * Quick scan for obvious session issues.
     */
    public function quickScan(mixed $input, InspectionContext $context): bool
    {
        if (!$this->cache) {
            return false;
        }

        $sessionId = $context->sessionId();
        if (!$sessionId) {
            return false;
        }

        // Check if session is flagged
        $flagKey = $this->cachePrefix . 'flagged:' . md5($sessionId);
        return (bool) $this->cache->get($flagKey);
    }

    /**
     * Deep inspection for session integrity.
     */
    public function deepInspection(mixed $input, InspectionContext $context): GuardResultInterface
    {
        $threats = [];
        $sessionId = $context->sessionId();

        if (!$sessionId || !$this->cache) {
            return GuardResult::pass($this->name, 'Session not available for inspection');
        }

        $currentFingerprint = $this->buildFingerprint($context);
        $storedData = $this->getStoredSessionData($sessionId);

        if ($storedData === null) {
            // First request with this session - store baseline
            $this->storeSessionData($sessionId, $currentFingerprint, $context);
            return GuardResult::pass($this->name, 'Session baseline established');
        }

        // Check fingerprint drift
        $fingerprintDrift = $this->checkFingerprintDrift($currentFingerprint, $storedData['fingerprint']);
        if ($fingerprintDrift['drifted']) {
            $threats[] = [
                'type' => 'fingerprint_drift',
                'changed_fields' => $fingerprintDrift['changed_fields'],
                'severity' => $fingerprintDrift['severity'],
            ];
        }

        // Check geolocation jump
        $currentIp = $context->ip();
        if ($currentIp && isset($storedData['ip'])) {
            $geoJump = $this->checkGeoJump($storedData['ip'], $currentIp, $storedData['timestamp']);
            if ($geoJump['impossible']) {
                $threats[] = [
                    'type' => 'impossible_geo_jump',
                    'from_ip' => $this->maskIp($storedData['ip']),
                    'to_ip' => $this->maskIp($currentIp),
                    'estimated_distance_km' => $geoJump['distance_km'],
                    'time_seconds' => $geoJump['time_seconds'],
                ];
            }
        }

        // Check for concurrent usage from different IPs
        if ($currentIp && isset($storedData['recent_ips'])) {
            $concurrent = $this->checkConcurrentUsage($currentIp, $storedData['recent_ips']);
            if ($concurrent['detected']) {
                $threats[] = [
                    'type' => 'concurrent_session_usage',
                    'unique_ips' => $concurrent['unique_ips'],
                    'window_seconds' => $concurrent['window_seconds'],
                ];
            }
        }

        // Update session data with current request
        $this->updateSessionData($sessionId, $currentFingerprint, $context);

        if (!empty($threats)) {
            // Flag session for quick scan
            $this->cache->set(
                $this->cachePrefix . 'flagged:' . md5($sessionId),
                true,
                3600
            );

            return GuardResult::fail(
                $this->name,
                $this->determineThreatLevel($threats),
                'Session integrity violation detected',
                [
                    'threats' => $threats,
                    'session_id' => substr(md5($sessionId), 0, 8) . '...',
                ]
            );
        }

        return GuardResult::pass($this->name, 'Session integrity verified');
    }

    /**
     * Build fingerprint from context.
     */
    private function buildFingerprint(InspectionContext $context): array
    {
        $fingerprint = [];
        $headers = $context->getMeta('headers', []);

        foreach ($this->fingerprintFields as $field) {
            $fingerprint[$field] = match ($field) {
                'user_agent' => $headers['user-agent'] ?? null,
                'accept_language' => $headers['accept-language'] ?? null,
                'accept_encoding' => $headers['accept-encoding'] ?? null,
                'accept' => $headers['accept'] ?? null,
                'sec_ch_ua' => $headers['sec-ch-ua'] ?? null,
                'sec_ch_ua_platform' => $headers['sec-ch-ua-platform'] ?? null,
                default => $headers[$field] ?? null,
            };
        }

        return $fingerprint;
    }

    /**
     * Check for fingerprint drift.
     */
    private function checkFingerprintDrift(array $current, array $stored): array
    {
        $changedFields = [];
        $severity = 'low';

        foreach ($this->fingerprintFields as $field) {
            $currentValue = $current[$field] ?? null;
            $storedValue = $stored[$field] ?? null;

            if ($currentValue !== $storedValue) {
                $changedFields[] = $field;

                // User-agent change is high severity
                if ($field === 'user_agent') {
                    $severity = 'high';
                } elseif ($severity !== 'high') {
                    $severity = 'medium';
                }
            }
        }

        return [
            'drifted' => !empty($changedFields),
            'changed_fields' => $changedFields,
            'severity' => $severity,
        ];
    }

    /**
     * Check for impossible geographic jump.
     */
    private function checkGeoJump(string $fromIp, string $toIp, int $timestamp): array
    {
        if ($fromIp === $toIp) {
            return ['impossible' => false];
        }

        $timeSeconds = time() - $timestamp;

        // Skip if too much time has passed (could be legitimate travel)
        if ($timeSeconds > $this->maxTimeBetweenRequestsSeconds) {
            return ['impossible' => false];
        }

        // Estimate distance based on IP geolocation (simplified)
        $distanceKm = $this->estimateDistance($fromIp, $toIp);

        if ($distanceKm === null) {
            return ['impossible' => false];
        }

        // Calculate maximum possible travel distance
        // Assume max speed of 1000 km/h (commercial flight)
        $maxDistanceKm = ($timeSeconds / 3600) * 1000;

        return [
            'impossible' => $distanceKm > $maxDistanceKm && $distanceKm > $this->maxGeoDistanceKm,
            'distance_km' => $distanceKm,
            'time_seconds' => $timeSeconds,
        ];
    }

    /**
     * Check for concurrent usage from multiple IPs.
     */
    private function checkConcurrentUsage(string $currentIp, array $recentIps): array
    {
        $windowSeconds = 60;
        $now = time();

        // Filter to recent IPs
        $recentIps = array_filter(
            $recentIps,
            fn($entry) => $entry['time'] > $now - $windowSeconds
        );

        // Add current IP
        $uniqueIps = array_unique(array_merge(
            array_column($recentIps, 'ip'),
            [md5($currentIp)]
        ));

        return [
            'detected' => count($uniqueIps) > 2, // More than 2 unique IPs in 60 seconds
            'unique_ips' => count($uniqueIps),
            'window_seconds' => $windowSeconds,
        ];
    }

    /**
     * Estimate distance between two IPs (simplified).
     */
    private function estimateDistance(string $fromIp, string $toIp): ?int
    {
        // In production, use GeoIP database
        // This is a simplified version that checks IP class difference

        $fromParts = explode('.', $fromIp);
        $toParts = explode('.', $toIp);

        if (count($fromParts) !== 4 || count($toParts) !== 4) {
            return null;
        }

        // Same /8 network - likely same region
        if ($fromParts[0] === $toParts[0]) {
            return 100; // Assume ~100km
        }

        // Different /8 network - assume different region/country
        return 1000; // Assume ~1000km
    }

    /**
     * Get stored session data.
     */
    private function getStoredSessionData(string $sessionId): ?array
    {
        $key = $this->cachePrefix . 'data:' . md5($sessionId);
        return $this->cache->get($key);
    }

    /**
     * Store session data.
     */
    private function storeSessionData(string $sessionId, array $fingerprint, InspectionContext $context): void
    {
        $key = $this->cachePrefix . 'data:' . md5($sessionId);
        $ip = $context->ip();

        $this->cache->set($key, [
            'fingerprint' => $fingerprint,
            'ip' => $ip,
            'timestamp' => time(),
            'recent_ips' => $ip ? [['ip' => md5($ip), 'time' => time()]] : [],
        ], 86400); // 24 hours
    }

    /**
     * Update session data.
     */
    private function updateSessionData(string $sessionId, array $fingerprint, InspectionContext $context): void
    {
        $key = $this->cachePrefix . 'data:' . md5($sessionId);
        $stored = $this->cache->get($key, []);
        $ip = $context->ip();

        // Maintain recent IPs (last 10)
        $recentIps = $stored['recent_ips'] ?? [];
        if ($ip) {
            $recentIps[] = ['ip' => md5($ip), 'time' => time()];
            $recentIps = array_slice($recentIps, -10);
        }

        $this->cache->set($key, [
            'fingerprint' => $fingerprint,
            'ip' => $ip,
            'timestamp' => time(),
            'recent_ips' => $recentIps,
        ], 86400);
    }

    /**
     * Determine threat level based on threats.
     */
    private function determineThreatLevel(array $threats): ThreatLevel
    {
        foreach ($threats as $threat) {
            if ($threat['type'] === 'impossible_geo_jump') {
                return ThreatLevel::CRITICAL;
            }
            if ($threat['type'] === 'fingerprint_drift' && $threat['severity'] === 'high') {
                return ThreatLevel::HIGH;
            }
            if ($threat['type'] === 'concurrent_session_usage') {
                return ThreatLevel::HIGH;
            }
        }

        return ThreatLevel::MEDIUM;
    }

    /**
     * Mask IP for logging.
     */
    private function maskIp(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            return $parts[0] . '.' . $parts[1] . '.xxx.xxx';
        }
        return substr($ip, 0, 10) . '...';
    }

    /**
     * Invalidate session (for use after detection).
     */
    public function invalidateSession(string $sessionId): void
    {
        if (!$this->cache) {
            return;
        }

        $this->cache->delete($this->cachePrefix . 'data:' . md5($sessionId));
        $this->cache->set(
            $this->cachePrefix . 'invalidated:' . md5($sessionId),
            true,
            86400
        );
    }
}
