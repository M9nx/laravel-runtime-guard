<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Analytics;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;

/**
 * STIX 2.1 Exporter.
 *
 * Exports threat intelligence in STIX 2.1 format for sharing.
 */
class StixExporter
{
    protected string $identity;
    protected string $identityId;

    public function __construct()
    {
        $this->identity = config('runtime-guard.analytics.stix.identity', 'RuntimeGuard');
        $this->identityId = 'identity--' . $this->generateUuid5($this->identity);
    }

    /**
     * Export a single threat as STIX bundle.
     */
    public function exportThreat(
        GuardResultInterface $result,
        array $context = []
    ): array {
        $objects = [];

        // Create identity
        $objects[] = $this->createIdentity();

        // Create indicator
        $indicator = $this->createIndicator($result, $context);
        $objects[] = $indicator;

        // Create attack pattern if applicable
        $attackPattern = $this->createAttackPattern($result, $context);
        if ($attackPattern) {
            $objects[] = $attackPattern;

            // Create relationship
            $objects[] = $this->createRelationship(
                $indicator['id'],
                $attackPattern['id'],
                'indicates'
            );
        }

        // Create observed data
        $observedData = $this->createObservedData($result, $context);
        if ($observedData) {
            $objects[] = $observedData;

            $objects[] = $this->createRelationship(
                $indicator['id'],
                $observedData['id'],
                'based-on'
            );
        }

        return $this->createBundle($objects);
    }

    /**
     * Export multiple threats as STIX bundle.
     */
    public function exportBatch(array $threats): array
    {
        $objects = [];
        $objects[] = $this->createIdentity();

        foreach ($threats as $threat) {
            $result = $threat['result'];
            $context = $threat['context'] ?? [];

            $indicator = $this->createIndicator($result, $context);
            $objects[] = $indicator;

            $attackPattern = $this->createAttackPattern($result, $context);
            if ($attackPattern) {
                $objects[] = $attackPattern;
                $objects[] = $this->createRelationship(
                    $indicator['id'],
                    $attackPattern['id'],
                    'indicates'
                );
            }
        }

        return $this->createBundle($objects);
    }

    /**
     * Create STIX bundle.
     */
    protected function createBundle(array $objects): array
    {
        return [
            'type' => 'bundle',
            'id' => 'bundle--' . $this->generateUuid4(),
            'objects' => $objects,
        ];
    }

    /**
     * Create identity object.
     */
    protected function createIdentity(): array
    {
        return [
            'type' => 'identity',
            'spec_version' => '2.1',
            'id' => $this->identityId,
            'created' => $this->formatTimestamp(time()),
            'modified' => $this->formatTimestamp(time()),
            'name' => $this->identity,
            'identity_class' => 'system',
            'sectors' => ['technology'],
        ];
    }

    /**
     * Create indicator object.
     */
    protected function createIndicator(GuardResultInterface $result, array $context): array
    {
        $details = $result->getDetails();
        $pattern = $this->buildStixPattern($result, $context);

        return [
            'type' => 'indicator',
            'spec_version' => '2.1',
            'id' => 'indicator--' . $this->generateUuid4(),
            'created' => $this->formatTimestamp($context['timestamp'] ?? time()),
            'modified' => $this->formatTimestamp($context['timestamp'] ?? time()),
            'created_by_ref' => $this->identityId,
            'name' => $result->getMessage() ?? 'Security threat detected',
            'description' => $this->buildDescription($result, $context),
            'indicator_types' => [$this->mapThreatType($context['guard'] ?? '')],
            'pattern' => $pattern,
            'pattern_type' => 'stix',
            'pattern_version' => '2.1',
            'valid_from' => $this->formatTimestamp($context['timestamp'] ?? time()),
            'confidence' => $this->mapConfidence($result->getThreatLevel()),
            'labels' => $this->buildLabels($result, $context),
        ];
    }

    /**
     * Create attack pattern object.
     */
    protected function createAttackPattern(GuardResultInterface $result, array $context): ?array
    {
        $guard = $context['guard'] ?? '';
        $mitre = $this->mapToMitre($guard);

        if (!$mitre) {
            return null;
        }

        return [
            'type' => 'attack-pattern',
            'spec_version' => '2.1',
            'id' => 'attack-pattern--' . $this->generateUuid5($mitre['id']),
            'created' => $this->formatTimestamp(time()),
            'modified' => $this->formatTimestamp(time()),
            'name' => $mitre['name'],
            'description' => $mitre['description'],
            'external_references' => [
                [
                    'source_name' => 'mitre-attack',
                    'external_id' => $mitre['id'],
                    'url' => "https://attack.mitre.org/techniques/{$mitre['id']}/",
                ],
            ],
            'kill_chain_phases' => $mitre['kill_chain'] ?? [],
        ];
    }

    /**
     * Create observed data object.
     */
    protected function createObservedData(GuardResultInterface $result, array $context): ?array
    {
        $objects = [];

        // Add network traffic if IP available
        if (isset($context['ip'])) {
            $objects['0'] = [
                'type' => 'ipv4-addr',
                'value' => $context['ip'],
            ];
        }

        // Add URL if path available
        if (isset($context['path'])) {
            $urlIndex = count($objects);
            $objects[(string)$urlIndex] = [
                'type' => 'url',
                'value' => ($context['scheme'] ?? 'https') . '://' .
                    ($context['host'] ?? 'example.com') . $context['path'],
            ];
        }

        if (empty($objects)) {
            return null;
        }

        return [
            'type' => 'observed-data',
            'spec_version' => '2.1',
            'id' => 'observed-data--' . $this->generateUuid4(),
            'created' => $this->formatTimestamp($context['timestamp'] ?? time()),
            'modified' => $this->formatTimestamp($context['timestamp'] ?? time()),
            'first_observed' => $this->formatTimestamp($context['timestamp'] ?? time()),
            'last_observed' => $this->formatTimestamp($context['timestamp'] ?? time()),
            'number_observed' => 1,
            'objects' => $objects,
        ];
    }

    /**
     * Create relationship object.
     */
    protected function createRelationship(string $sourceId, string $targetId, string $type): array
    {
        return [
            'type' => 'relationship',
            'spec_version' => '2.1',
            'id' => 'relationship--' . $this->generateUuid4(),
            'created' => $this->formatTimestamp(time()),
            'modified' => $this->formatTimestamp(time()),
            'relationship_type' => $type,
            'source_ref' => $sourceId,
            'target_ref' => $targetId,
        ];
    }

    /**
     * Build STIX pattern from result.
     */
    protected function buildStixPattern(GuardResultInterface $result, array $context): string
    {
        $parts = [];

        // Add IP pattern if available
        if (isset($context['ip'])) {
            $parts[] = "[ipv4-addr:value = '{$context['ip']}']";
        }

        // Add URL pattern if available
        if (isset($context['path'])) {
            $escapedPath = addslashes($context['path']);
            $parts[] = "[url:value LIKE '%{$escapedPath}%']";
        }

        // Add HTTP request pattern
        if (isset($context['method'])) {
            $parts[] = "[http-request-ext:request_method = '{$context['method']}']";
        }

        if (empty($parts)) {
            return "[artifact:payload_bin != '']"; // Fallback pattern
        }

        return implode(' AND ', $parts);
    }

    /**
     * Build description from result and context.
     */
    protected function buildDescription(GuardResultInterface $result, array $context): string
    {
        $desc = $result->getMessage() ?? 'Security threat detected';

        if ($guard = ($context['guard'] ?? '')) {
            $desc .= " (Guard: {$guard})";
        }

        if ($level = $result->getThreatLevel()) {
            $desc .= " - Severity: {$level->name}";
        }

        return $desc;
    }

    /**
     * Build labels array.
     */
    protected function buildLabels(GuardResultInterface $result, array $context): array
    {
        $labels = ['runtime-guard'];

        if ($guard = ($context['guard'] ?? '')) {
            $labels[] = "guard:{$guard}";
        }

        if ($level = $result->getThreatLevel()) {
            $labels[] = "severity:{$level->name}";
        }

        return $labels;
    }

    /**
     * Map guard to indicator type.
     */
    protected function mapThreatType(string $guard): string
    {
        return match ($guard) {
            'sql-injection', 'nosql-injection' => 'malicious-activity',
            'xss' => 'malicious-activity',
            'command-injection' => 'malicious-activity',
            'ssrf' => 'anomalous-activity',
            'mass-assignment' => 'anomalous-activity',
            default => 'unknown',
        };
    }

    /**
     * Map threat level to STIX confidence.
     */
    protected function mapConfidence($level): int
    {
        if (!$level) {
            return 50;
        }

        return match ($level->value) {
            4 => 95, // CRITICAL
            3 => 85, // HIGH
            2 => 70, // MEDIUM
            1 => 50, // LOW
            default => 50,
        };
    }

    /**
     * Map guard to MITRE ATT&CK.
     */
    protected function mapToMitre(string $guard): ?array
    {
        $mappings = [
            'sql-injection' => [
                'id' => 'T1190',
                'name' => 'Exploit Public-Facing Application',
                'description' => 'SQL Injection attack detected',
                'kill_chain' => [
                    ['kill_chain_name' => 'mitre-attack', 'phase_name' => 'initial-access'],
                ],
            ],
            'command-injection' => [
                'id' => 'T1059',
                'name' => 'Command and Scripting Interpreter',
                'description' => 'Command injection attack detected',
                'kill_chain' => [
                    ['kill_chain_name' => 'mitre-attack', 'phase_name' => 'execution'],
                ],
            ],
            'ssrf' => [
                'id' => 'T1090',
                'name' => 'Proxy',
                'description' => 'Server-Side Request Forgery detected',
                'kill_chain' => [
                    ['kill_chain_name' => 'mitre-attack', 'phase_name' => 'command-and-control'],
                ],
            ],
            'xss' => [
                'id' => 'T1059.007',
                'name' => 'JavaScript',
                'description' => 'Cross-Site Scripting attack detected',
                'kill_chain' => [
                    ['kill_chain_name' => 'mitre-attack', 'phase_name' => 'execution'],
                ],
            ],
        ];

        return $mappings[$guard] ?? null;
    }

    /**
     * Format timestamp as STIX format.
     */
    protected function formatTimestamp(int $timestamp): string
    {
        return gmdate('Y-m-d\TH:i:s.000\Z', $timestamp);
    }

    /**
     * Generate UUID v4.
     */
    protected function generateUuid4(): string
    {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * Generate UUID v5 (deterministic).
     */
    protected function generateUuid5(string $name): string
    {
        $namespace = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'; // URL namespace
        $hash = sha1(hex2bin(str_replace('-', '', $namespace)) . $name);

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hash, 0, 8),
            substr($hash, 8, 4),
            '5' . substr($hash, 13, 3),
            dechex(hexdec(substr($hash, 16, 2)) & 0x3f | 0x80) . substr($hash, 18, 2),
            substr($hash, 20, 12)
        );
    }

    /**
     * Export to JSON string.
     */
    public function toJson(array $bundle): string
    {
        return json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
