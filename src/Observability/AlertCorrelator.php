<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Observability;

use Illuminate\Support\Facades\Cache;

/**
 * Alert Correlator.
 *
 * Correlates and groups related security alerts:
 * - Pattern-based correlation
 * - Temporal correlation
 * - Source-based grouping
 * - Alert deduplication
 */
class AlertCorrelator
{
    private array $config;
    private array $correlationRules;

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'correlation_window' => 300, // 5 minutes
            'similarity_threshold' => 0.7,
            'max_group_size' => 100,
            'dedup_window' => 60,
        ], $config);

        $this->correlationRules = $this->getDefaultRules();
    }

    /**
     * Process new alert.
     */
    public function process(Alert $alert): CorrelationResult
    {
        // Check for duplicates
        if ($this->isDuplicate($alert)) {
            return new CorrelationResult(
                alert: $alert,
                action: 'deduplicated',
                groupId: null,
                correlatedAlerts: []
            );
        }

        // Find correlations
        $correlations = $this->findCorrelations($alert);

        if (!empty($correlations)) {
            $groupId = $this->addToGroup($alert, $correlations);

            return new CorrelationResult(
                alert: $alert,
                action: 'correlated',
                groupId: $groupId,
                correlatedAlerts: $correlations
            );
        }

        // Create new group
        $groupId = $this->createGroup($alert);

        return new CorrelationResult(
            alert: $alert,
            action: 'new_group',
            groupId: $groupId,
            correlatedAlerts: []
        );
    }

    /**
     * Get alert groups.
     */
    public function getGroups(int $limit = 50): array
    {
        $groupIds = Cache::get('alert:groups:index', []);
        $groups = [];

        foreach (array_slice($groupIds, 0, $limit) as $groupId) {
            $group = $this->getGroup($groupId);
            if ($group !== null) {
                $groups[] = $group;
            }
        }

        // Sort by severity and recency
        usort($groups, function ($a, $b) {
            $severityOrder = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
            $severityCompare = ($severityOrder[$b['severity']] ?? 0) <=> ($severityOrder[$a['severity']] ?? 0);
            if ($severityCompare !== 0) return $severityCompare;
            return $b['last_seen'] <=> $a['last_seen'];
        });

        return $groups;
    }

    /**
     * Get specific group.
     */
    public function getGroup(string $groupId): ?array
    {
        return Cache::get("alert:group:{$groupId}");
    }

    /**
     * Acknowledge group.
     */
    public function acknowledgeGroup(string $groupId, string $acknowledgedBy): void
    {
        $group = $this->getGroup($groupId);
        if ($group === null) return;

        $group['acknowledged'] = true;
        $group['acknowledged_by'] = $acknowledgedBy;
        $group['acknowledged_at'] = time();

        Cache::put("alert:group:{$groupId}", $group, 86400);
    }

    /**
     * Resolve group.
     */
    public function resolveGroup(string $groupId, string $resolvedBy, ?string $resolution = null): void
    {
        $group = $this->getGroup($groupId);
        if ($group === null) return;

        $group['resolved'] = true;
        $group['resolved_by'] = $resolvedBy;
        $group['resolved_at'] = time();
        $group['resolution'] = $resolution;

        Cache::put("alert:group:{$groupId}", $group, 86400);

        // Remove from active index
        $this->removeFromIndex($groupId);
    }

    /**
     * Get correlation statistics.
     */
    public function getStats(): array
    {
        return [
            'total_groups' => count(Cache::get('alert:groups:index', [])),
            'unacknowledged' => $this->countUnacknowledged(),
            'by_severity' => $this->countBySeverity(),
            'correlation_rate' => Cache::get('alert:stats:correlation_rate', 0),
            'dedup_rate' => Cache::get('alert:stats:dedup_rate', 0),
        ];
    }

    /**
     * Add correlation rule.
     */
    public function addRule(string $name, array $rule): void
    {
        $this->correlationRules[$name] = $rule;
    }

    /**
     * Check if alert is duplicate.
     */
    private function isDuplicate(Alert $alert): bool
    {
        $hash = $this->generateAlertHash($alert);
        $key = "alert:dedup:{$hash}";

        if (Cache::has($key)) {
            $this->incrementStat('dedup_count');
            return true;
        }

        Cache::put($key, true, $this->config['dedup_window']);
        return false;
    }

    /**
     * Find correlations for alert.
     */
    private function findCorrelations(Alert $alert): array
    {
        $correlations = [];
        $recentAlerts = $this->getRecentAlerts();

        foreach ($recentAlerts as $recent) {
            $similarity = $this->calculateSimilarity($alert, $recent);

            if ($similarity >= $this->config['similarity_threshold']) {
                $correlations[] = [
                    'alert' => $recent,
                    'similarity' => $similarity,
                    'rules_matched' => $this->matchRules($alert, $recent),
                ];
            }
        }

        if (!empty($correlations)) {
            $this->incrementStat('correlation_count');
        }

        return $correlations;
    }

    /**
     * Calculate similarity between alerts.
     */
    private function calculateSimilarity(Alert $alert1, array $alert2): float
    {
        $score = 0;
        $weights = [
            'type' => 0.3,
            'source_ip' => 0.2,
            'target' => 0.2,
            'severity' => 0.15,
            'temporal' => 0.15,
        ];

        // Type similarity
        if ($alert1->type === ($alert2['type'] ?? '')) {
            $score += $weights['type'];
        }

        // Source IP similarity
        if ($alert1->sourceIp === ($alert2['source_ip'] ?? '')) {
            $score += $weights['source_ip'];
        } elseif ($this->sameSubnet($alert1->sourceIp, $alert2['source_ip'] ?? '')) {
            $score += $weights['source_ip'] * 0.5;
        }

        // Target similarity
        if ($alert1->target === ($alert2['target'] ?? '')) {
            $score += $weights['target'];
        }

        // Severity similarity
        if ($alert1->severity === ($alert2['severity'] ?? '')) {
            $score += $weights['severity'];
        }

        // Temporal proximity
        $timeDiff = abs($alert1->timestamp - ($alert2['timestamp'] ?? 0));
        if ($timeDiff <= $this->config['correlation_window']) {
            $temporalScore = 1 - ($timeDiff / $this->config['correlation_window']);
            $score += $weights['temporal'] * $temporalScore;
        }

        return $score;
    }

    /**
     * Match correlation rules.
     */
    private function matchRules(Alert $alert1, array $alert2): array
    {
        $matched = [];

        foreach ($this->correlationRules as $name => $rule) {
            if ($this->ruleMatches($rule, $alert1, $alert2)) {
                $matched[] = $name;
            }
        }

        return $matched;
    }

    /**
     * Check if rule matches.
     */
    private function ruleMatches(array $rule, Alert $alert1, array $alert2): bool
    {
        foreach ($rule['conditions'] ?? [] as $field => $condition) {
            $value1 = $this->getFieldValue($alert1, $field);
            $value2 = $alert2[$field] ?? null;

            if ($condition === 'equals' && $value1 !== $value2) {
                return false;
            }

            if ($condition === 'same_subnet' && !$this->sameSubnet($value1, $value2)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get field value from alert.
     */
    private function getFieldValue(Alert $alert, string $field): mixed
    {
        return match ($field) {
            'type' => $alert->type,
            'source_ip' => $alert->sourceIp,
            'target' => $alert->target,
            'severity' => $alert->severity,
            default => $alert->metadata[$field] ?? null,
        };
    }

    /**
     * Check if IPs are in same subnet.
     */
    private function sameSubnet(?string $ip1, ?string $ip2): bool
    {
        if ($ip1 === null || $ip2 === null) return false;

        $parts1 = explode('.', $ip1);
        $parts2 = explode('.', $ip2);

        return count($parts1) >= 3 && count($parts2) >= 3
            && $parts1[0] === $parts2[0]
            && $parts1[1] === $parts2[1]
            && $parts1[2] === $parts2[2];
    }

    /**
     * Create new alert group.
     */
    private function createGroup(Alert $alert): string
    {
        $groupId = 'grp_' . bin2hex(random_bytes(8));

        $group = [
            'id' => $groupId,
            'type' => $alert->type,
            'severity' => $alert->severity,
            'first_seen' => $alert->timestamp,
            'last_seen' => $alert->timestamp,
            'count' => 1,
            'alerts' => [$this->alertToArray($alert)],
            'source_ips' => [$alert->sourceIp],
            'targets' => [$alert->target],
            'acknowledged' => false,
            'resolved' => false,
        ];

        Cache::put("alert:group:{$groupId}", $group, 86400);
        $this->addToIndex($groupId);
        $this->storeRecentAlert($alert);

        return $groupId;
    }

    /**
     * Add alert to existing group.
     */
    private function addToGroup(Alert $alert, array $correlations): string
    {
        // Find best matching group
        $bestMatch = $correlations[0];
        $groupId = $bestMatch['alert']['group_id'] ?? null;

        if ($groupId === null) {
            return $this->createGroup($alert);
        }

        $group = $this->getGroup($groupId);
        if ($group === null) {
            return $this->createGroup($alert);
        }

        // Update group
        $group['last_seen'] = $alert->timestamp;
        $group['count']++;

        if (count($group['alerts']) < $this->config['max_group_size']) {
            $group['alerts'][] = $this->alertToArray($alert);
        }

        if (!in_array($alert->sourceIp, $group['source_ips'])) {
            $group['source_ips'][] = $alert->sourceIp;
        }

        if (!in_array($alert->target, $group['targets'])) {
            $group['targets'][] = $alert->target;
        }

        // Escalate severity if needed
        $group['severity'] = $this->maxSeverity($group['severity'], $alert->severity);

        Cache::put("alert:group:{$groupId}", $group, 86400);
        $this->storeRecentAlert($alert, $groupId);

        return $groupId;
    }

    /**
     * Generate alert hash for deduplication.
     */
    private function generateAlertHash(Alert $alert): string
    {
        return md5(implode('|', [
            $alert->type,
            $alert->sourceIp,
            $alert->target,
            $alert->severity,
        ]));
    }

    /**
     * Get recent alerts for correlation.
     */
    private function getRecentAlerts(): array
    {
        return Cache::get('alert:recent', []);
    }

    /**
     * Store alert in recent list.
     */
    private function storeRecentAlert(Alert $alert, ?string $groupId = null): void
    {
        $recent = Cache::get('alert:recent', []);

        $alertData = $this->alertToArray($alert);
        $alertData['group_id'] = $groupId;

        array_unshift($recent, $alertData);

        // Keep only alerts within correlation window
        $cutoff = time() - $this->config['correlation_window'];
        $recent = array_filter($recent, fn($a) => ($a['timestamp'] ?? 0) >= $cutoff);

        Cache::put('alert:recent', array_slice($recent, 0, 1000), $this->config['correlation_window']);
    }

    /**
     * Convert alert to array.
     */
    private function alertToArray(Alert $alert): array
    {
        return [
            'id' => $alert->id,
            'type' => $alert->type,
            'severity' => $alert->severity,
            'source_ip' => $alert->sourceIp,
            'target' => $alert->target,
            'message' => $alert->message,
            'timestamp' => $alert->timestamp,
            'metadata' => $alert->metadata,
        ];
    }

    /**
     * Add group to index.
     */
    private function addToIndex(string $groupId): void
    {
        $index = Cache::get('alert:groups:index', []);
        array_unshift($index, $groupId);
        Cache::put('alert:groups:index', array_slice($index, 0, 1000), 86400);
    }

    /**
     * Remove group from index.
     */
    private function removeFromIndex(string $groupId): void
    {
        $index = Cache::get('alert:groups:index', []);
        $index = array_filter($index, fn($id) => $id !== $groupId);
        Cache::put('alert:groups:index', $index, 86400);
    }

    /**
     * Get maximum severity.
     */
    private function maxSeverity(string $sev1, string $sev2): string
    {
        $order = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        return ($order[$sev1] ?? 0) >= ($order[$sev2] ?? 0) ? $sev1 : $sev2;
    }

    /**
     * Increment statistic.
     */
    private function incrementStat(string $stat): void
    {
        Cache::increment("alert:stats:{$stat}");
    }

    /**
     * Count unacknowledged groups.
     */
    private function countUnacknowledged(): int
    {
        $groups = $this->getGroups(100);
        return count(array_filter($groups, fn($g) => !($g['acknowledged'] ?? false)));
    }

    /**
     * Count groups by severity.
     */
    private function countBySeverity(): array
    {
        $groups = $this->getGroups(100);
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];

        foreach ($groups as $group) {
            $severity = $group['severity'] ?? 'medium';
            $counts[$severity] = ($counts[$severity] ?? 0) + 1;
        }

        return $counts;
    }

    /**
     * Get default correlation rules.
     */
    private function getDefaultRules(): array
    {
        return [
            'same_source_attack' => [
                'conditions' => ['source_ip' => 'equals', 'type' => 'equals'],
            ],
            'distributed_attack' => [
                'conditions' => ['target' => 'equals', 'type' => 'equals'],
            ],
            'subnet_scan' => [
                'conditions' => ['source_ip' => 'same_subnet', 'type' => 'equals'],
            ],
        ];
    }
}

/**
 * Alert.
 */
class Alert
{
    public function __construct(
        public readonly string $id,
        public readonly string $type,
        public readonly string $severity,
        public readonly ?string $sourceIp,
        public readonly ?string $target,
        public readonly string $message,
        public readonly int $timestamp,
        public readonly array $metadata = []
    ) {}

    public static function create(array $data): self
    {
        return new self(
            $data['id'] ?? 'alert_' . bin2hex(random_bytes(8)),
            $data['type'] ?? 'unknown',
            $data['severity'] ?? 'medium',
            $data['source_ip'] ?? null,
            $data['target'] ?? null,
            $data['message'] ?? '',
            $data['timestamp'] ?? time(),
            $data['metadata'] ?? []
        );
    }
}

/**
 * Correlation Result.
 */
class CorrelationResult
{
    public function __construct(
        public readonly Alert $alert,
        public readonly string $action,
        public readonly ?string $groupId,
        public readonly array $correlatedAlerts
    ) {}

    public function wasCorrelated(): bool
    {
        return $this->action === 'correlated';
    }

    public function wasDeduplicated(): bool
    {
        return $this->action === 'deduplicated';
    }
}
