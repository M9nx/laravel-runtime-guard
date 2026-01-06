<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\MultiTenant;

use Illuminate\Support\Facades\Cache;

/**
 * Cross-Tenant Intelligence.
 *
 * Shares threat intelligence across tenants:
 * - Anonymous threat pattern sharing
 * - Cross-tenant attack correlation
 * - Collective defense mechanisms
 * - Privacy-preserving intelligence
 */
class CrossTenantIntelligence
{
    private array $config;
    private array $localIntel = [];

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'enabled' => true,
            'sharing_level' => 'anonymized', // none, anonymized, full
            'min_confidence' => 0.7,
            'cache_ttl' => 1800,
            'contribution_required' => true,
        ], $config);
    }

    /**
     * Report threat from tenant.
     */
    public function reportThreat(ThreatReport $report): void
    {
        if (!$this->config['enabled']) {
            return;
        }

        // Anonymize based on sharing level
        $anonymized = $this->anonymizeReport($report);

        // Store in shared intelligence
        $this->storeIntelligence($anonymized);

        // Update pattern statistics
        $this->updatePatternStats($anonymized);
    }

    /**
     * Get shared intelligence for pattern.
     */
    public function getIntelligence(string $pattern): ?SharedIntelligence
    {
        $cacheKey = "intel:pattern:" . md5($pattern);
        $cached = Cache::get($cacheKey);

        if ($cached !== null) {
            return SharedIntelligence::fromArray($cached);
        }

        return null;
    }

    /**
     * Query intelligence by type.
     */
    public function queryByType(string $threatType, int $limit = 100): array
    {
        $cacheKey = "intel:type:{$threatType}";
        return Cache::get($cacheKey, []);
    }

    /**
     * Get threat indicators.
     */
    public function getThreatIndicators(): array
    {
        return [
            'ip_addresses' => $this->getIndicatorsByType('ip'),
            'patterns' => $this->getIndicatorsByType('pattern'),
            'user_agents' => $this->getIndicatorsByType('user_agent'),
            'payloads' => $this->getIndicatorsByType('payload_hash'),
        ];
    }

    /**
     * Check if indicator is known threat.
     */
    public function isKnownThreat(string $type, string $indicator): ThreatCheckResult
    {
        $cacheKey = "intel:indicator:{$type}:" . md5($indicator);
        $data = Cache::get($cacheKey);

        if ($data === null) {
            return new ThreatCheckResult(
                known: false,
                confidence: 0,
                reportCount: 0
            );
        }

        return new ThreatCheckResult(
            known: $data['confidence'] >= $this->config['min_confidence'],
            confidence: $data['confidence'],
            reportCount: $data['report_count'],
            firstSeen: $data['first_seen'] ?? null,
            lastSeen: $data['last_seen'] ?? null,
            threatTypes: $data['threat_types'] ?? []
        );
    }

    /**
     * Get cross-tenant attack correlation.
     */
    public function correlateAttack(array $indicators): CorrelationResult
    {
        $correlations = [];
        $affectedTenants = 0;
        $totalReports = 0;

        foreach ($indicators as $type => $value) {
            $check = $this->isKnownThreat($type, $value);
            if ($check->known) {
                $correlations[$type] = [
                    'confidence' => $check->confidence,
                    'report_count' => $check->reportCount,
                ];
                $totalReports += $check->reportCount;
            }
        }

        // Get unique tenant count (anonymized)
        $tenantKey = "intel:tenant_count:" . md5(serialize($indicators));
        $affectedTenants = Cache::get($tenantKey, 0);

        $isCoordinated = $affectedTenants >= 3 && $totalReports >= 10;

        return new CorrelationResult(
            correlated: !empty($correlations),
            indicators: $correlations,
            affectedTenantCount: $affectedTenants,
            totalReports: $totalReports,
            isCoordinatedAttack: $isCoordinated
        );
    }

    /**
     * Get collective defense recommendations.
     */
    public function getDefenseRecommendations(): array
    {
        $recommendations = [];

        // Get trending threats
        $trending = $this->getTrendingThreats();

        foreach ($trending as $threat) {
            $recommendations[] = [
                'type' => $threat['type'],
                'pattern' => $threat['pattern'] ?? null,
                'action' => $this->recommendAction($threat),
                'confidence' => $threat['confidence'],
                'urgency' => $this->calculateUrgency($threat),
            ];
        }

        return $recommendations;
    }

    /**
     * Get intelligence statistics.
     */
    public function getStats(): array
    {
        return [
            'total_reports' => Cache::get('intel:stats:total_reports', 0),
            'unique_patterns' => Cache::get('intel:stats:unique_patterns', 0),
            'contributing_tenants' => Cache::get('intel:stats:contributing_tenants', 0),
            'threats_blocked' => Cache::get('intel:stats:threats_blocked', 0),
            'last_update' => Cache::get('intel:stats:last_update'),
        ];
    }

    /**
     * Anonymize threat report.
     */
    private function anonymizeReport(ThreatReport $report): array
    {
        $data = [
            'threat_type' => $report->threatType,
            'confidence' => $report->confidence,
            'timestamp' => time(),
        ];

        switch ($this->config['sharing_level']) {
            case 'full':
                $data['tenant_id'] = $report->tenantId;
                $data['ip'] = $report->ip;
                $data['pattern'] = $report->pattern;
                $data['payload_hash'] = $report->payloadHash;
                break;

            case 'anonymized':
                $data['tenant_hash'] = hash('sha256', $report->tenantId);
                $data['ip_prefix'] = $this->anonymizeIp($report->ip);
                $data['pattern_hash'] = hash('sha256', $report->pattern ?? '');
                $data['payload_hash'] = $report->payloadHash;
                break;

            case 'none':
            default:
                // Only share threat type and confidence
                break;
        }

        return $data;
    }

    /**
     * Anonymize IP address.
     */
    private function anonymizeIp(?string $ip): ?string
    {
        if ($ip === null) {
            return null;
        }

        $parts = explode('.', $ip);
        if (count($parts) === 4) {
            return "{$parts[0]}.{$parts[1]}.0.0/16";
        }

        return null;
    }

    /**
     * Store intelligence data.
     */
    private function storeIntelligence(array $data): void
    {
        // Store by pattern hash
        if (!empty($data['pattern_hash'])) {
            $key = "intel:pattern:{$data['pattern_hash']}";
            $existing = Cache::get($key, [
                'report_count' => 0,
                'confidence' => 0,
                'first_seen' => time(),
                'threat_types' => [],
            ]);

            $existing['report_count']++;
            $existing['confidence'] = min(1.0, $existing['confidence'] + 0.1);
            $existing['last_seen'] = time();
            $existing['threat_types'][] = $data['threat_type'];
            $existing['threat_types'] = array_unique($existing['threat_types']);

            Cache::put($key, $existing, $this->config['cache_ttl']);
        }

        // Store by IP prefix
        if (!empty($data['ip_prefix'])) {
            $key = "intel:indicator:ip:" . md5($data['ip_prefix']);
            $this->incrementIndicator($key, $data);
        }

        // Update total stats
        Cache::increment('intel:stats:total_reports');
    }

    /**
     * Increment indicator count.
     */
    private function incrementIndicator(string $key, array $data): void
    {
        $existing = Cache::get($key, [
            'report_count' => 0,
            'confidence' => 0,
            'first_seen' => time(),
            'threat_types' => [],
        ]);

        $existing['report_count']++;
        $existing['confidence'] = min(1.0, ($existing['confidence'] * 0.9) + ($data['confidence'] * 0.1));
        $existing['last_seen'] = time();
        
        if (!empty($data['threat_type'])) {
            $existing['threat_types'][] = $data['threat_type'];
            $existing['threat_types'] = array_unique($existing['threat_types']);
        }

        Cache::put($key, $existing, $this->config['cache_ttl']);
    }

    /**
     * Update pattern statistics.
     */
    private function updatePatternStats(array $data): void
    {
        $statsKey = "intel:pattern_stats";
        $stats = Cache::get($statsKey, []);

        $type = $data['threat_type'];
        if (!isset($stats[$type])) {
            $stats[$type] = ['count' => 0, 'last_seen' => null];
        }

        $stats[$type]['count']++;
        $stats[$type]['last_seen'] = time();

        Cache::put($statsKey, $stats, $this->config['cache_ttl']);
    }

    /**
     * Get indicators by type.
     */
    private function getIndicatorsByType(string $type): array
    {
        return Cache::get("intel:indicators:{$type}", []);
    }

    /**
     * Get trending threats.
     */
    private function getTrendingThreats(): array
    {
        $stats = Cache::get('intel:pattern_stats', []);
        $trending = [];

        foreach ($stats as $type => $data) {
            if ($data['count'] >= 5 && (time() - $data['last_seen']) < 3600) {
                $trending[] = [
                    'type' => $type,
                    'count' => $data['count'],
                    'confidence' => min(1.0, $data['count'] / 100),
                    'last_seen' => $data['last_seen'],
                ];
            }
        }

        usort($trending, fn($a, $b) => $b['count'] <=> $a['count']);

        return array_slice($trending, 0, 10);
    }

    /**
     * Recommend action for threat.
     */
    private function recommendAction(array $threat): string
    {
        if ($threat['confidence'] >= 0.9) {
            return 'block';
        } elseif ($threat['confidence'] >= 0.7) {
            return 'challenge';
        } elseif ($threat['confidence'] >= 0.5) {
            return 'monitor';
        }

        return 'log';
    }

    /**
     * Calculate urgency level.
     */
    private function calculateUrgency(array $threat): string
    {
        $recency = time() - ($threat['last_seen'] ?? time());
        $volume = $threat['count'] ?? 0;

        if ($recency < 300 && $volume >= 50) {
            return 'critical';
        } elseif ($recency < 900 && $volume >= 20) {
            return 'high';
        } elseif ($recency < 3600 && $volume >= 10) {
            return 'medium';
        }

        return 'low';
    }
}

/**
 * Threat Report.
 */
class ThreatReport
{
    public function __construct(
        public readonly string $tenantId,
        public readonly string $threatType,
        public readonly float $confidence,
        public readonly ?string $ip = null,
        public readonly ?string $pattern = null,
        public readonly ?string $payloadHash = null,
        public readonly array $metadata = []
    ) {}
}

/**
 * Shared Intelligence.
 */
class SharedIntelligence
{
    public function __construct(
        public readonly string $patternHash,
        public readonly int $reportCount,
        public readonly float $confidence,
        public readonly array $threatTypes,
        public readonly ?int $firstSeen = null,
        public readonly ?int $lastSeen = null
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['pattern_hash'] ?? '',
            $data['report_count'] ?? 0,
            $data['confidence'] ?? 0,
            $data['threat_types'] ?? [],
            $data['first_seen'] ?? null,
            $data['last_seen'] ?? null
        );
    }
}

/**
 * Threat Check Result.
 */
class ThreatCheckResult
{
    public function __construct(
        public readonly bool $known,
        public readonly float $confidence,
        public readonly int $reportCount,
        public readonly ?int $firstSeen = null,
        public readonly ?int $lastSeen = null,
        public readonly array $threatTypes = []
    ) {}
}

/**
 * Correlation Result.
 */
class CorrelationResult
{
    public function __construct(
        public readonly bool $correlated,
        public readonly array $indicators,
        public readonly int $affectedTenantCount,
        public readonly int $totalReports,
        public readonly bool $isCoordinatedAttack
    ) {}
}
