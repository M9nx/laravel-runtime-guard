<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Analytics;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Support\InspectionContext;
use M9nx\RuntimeGuard\Support\RingBuffer;
use Psr\SimpleCache\CacheInterface;

/**
 * Reconstructs attack chains from individual events.
 *
 * Correlates multiple low-severity events to detect sophisticated attacks
 * that follow patterns like: reconnaissance → exploitation → exfiltration.
 */
class AttackChainReconstructor
{
    private ?CacheInterface $cache;
    private string $cachePrefix = 'runtime_guard:chains:';

    private int $windowMinutes;
    private int $minEvents;
    private array $chainPatterns;
    private RingBuffer $eventBuffer;

    /**
     * Known attack chain patterns.
     */
    private const DEFAULT_PATTERNS = [
        'reconnaissance_to_exploit' => [
            'stages' => ['scan', 'probe', 'exploit'],
            'guards' => [
                'scan' => ['anomaly', 'credential_stuffing'],
                'probe' => ['sql_injection', 'nosql_injection', 'ssrf'],
                'exploit' => ['command_injection', 'deserialization'],
            ],
            'max_stage_gap_seconds' => 300,
            'severity' => 'critical',
        ],
        'credential_attack' => [
            'stages' => ['enum', 'spray', 'access'],
            'guards' => [
                'enum' => ['credential_stuffing'],
                'spray' => ['credential_stuffing'],
                'access' => ['session_integrity', 'mass_assignment'],
            ],
            'max_stage_gap_seconds' => 600,
            'severity' => 'high',
        ],
        'data_exfiltration' => [
            'stages' => ['access', 'gather', 'exfil'],
            'guards' => [
                'access' => ['sql_injection', 'nosql_injection'],
                'gather' => ['sql_injection', 'graphql'],
                'exfil' => ['ssrf', 'file_operation'],
            ],
            'max_stage_gap_seconds' => 900,
            'severity' => 'critical',
        ],
        'injection_chain' => [
            'stages' => ['test', 'exploit', 'escalate'],
            'guards' => [
                'test' => ['sql_injection', 'xss'],
                'exploit' => ['sql_injection', 'command_injection'],
                'escalate' => ['mass_assignment', 'deserialization'],
            ],
            'max_stage_gap_seconds' => 180,
            'severity' => 'critical',
        ],
    ];

    public function __construct(array $config = [], ?CacheInterface $cache = null)
    {
        $this->cache = $cache;
        $this->windowMinutes = $config['window_minutes'] ?? 15;
        $this->minEvents = $config['min_events'] ?? 3;
        $this->chainPatterns = array_merge(
            self::DEFAULT_PATTERNS,
            $config['custom_patterns'] ?? []
        );
        $this->eventBuffer = new RingBuffer($config['buffer_size'] ?? 1000);
    }

    /**
     * Create from configuration.
     */
    public static function fromConfig(array $config, ?CacheInterface $cache = null): self
    {
        return new self($config, $cache);
    }

    /**
     * Record a security event for chain analysis.
     */
    public function recordEvent(GuardResultInterface $result, InspectionContext $context): void
    {
        if ($result->passed()) {
            return;
        }

        $event = [
            'timestamp' => time(),
            'guard' => $result->getGuardName(),
            'threat_level' => $result->getThreatLevel()->value,
            'ip' => $context->ip(),
            'user_id' => $context->userId(),
            'session_id' => $context->sessionId(),
            'path' => $context->path(),
            'metadata' => $result->getMetadata(),
        ];

        $this->eventBuffer->push($event);

        // Store in cache for cross-request correlation
        if ($this->cache && $context->ip()) {
            $this->storeEventForIp($context->ip(), $event);
        }

        if ($this->cache && $context->userId()) {
            $this->storeEventForUser($context->userId(), $event);
        }
    }

    /**
     * Analyze events and detect attack chains.
     *
     * @return array<array{pattern: string, events: array, severity: string, confidence: float}>
     */
    public function analyzeChains(?string $ip = null, ?string $userId = null): array
    {
        $events = $this->getRelevantEvents($ip, $userId);

        if (count($events) < $this->minEvents) {
            return [];
        }

        $detectedChains = [];

        foreach ($this->chainPatterns as $patternName => $pattern) {
            $chain = $this->matchPattern($events, $pattern);

            if ($chain !== null) {
                $detectedChains[] = [
                    'pattern' => $patternName,
                    'events' => $chain['events'],
                    'stages_matched' => $chain['stages_matched'],
                    'severity' => $pattern['severity'],
                    'confidence' => $chain['confidence'],
                    'timeline' => $this->buildTimeline($chain['events']),
                ];
            }
        }

        // Sort by severity and confidence
        usort($detectedChains, function ($a, $b) {
            $severityOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
            $severityDiff = ($severityOrder[$a['severity']] ?? 4) - ($severityOrder[$b['severity']] ?? 4);

            if ($severityDiff !== 0) {
                return $severityDiff;
            }

            return $b['confidence'] <=> $a['confidence'];
        });

        return $detectedChains;
    }

    /**
     * Get the most likely current attack stage.
     */
    public function getCurrentStage(?string $ip = null, ?string $userId = null): ?array
    {
        $chains = $this->analyzeChains($ip, $userId);

        if (empty($chains)) {
            return null;
        }

        $topChain = $chains[0];
        $stages = $this->chainPatterns[$topChain['pattern']]['stages'] ?? [];
        $matchedStages = $topChain['stages_matched'];

        // Find next expected stage
        $currentStageIndex = count($matchedStages) - 1;
        $nextStageIndex = $currentStageIndex + 1;

        return [
            'chain_pattern' => $topChain['pattern'],
            'current_stage' => $stages[$currentStageIndex] ?? null,
            'next_expected_stage' => $stages[$nextStageIndex] ?? null,
            'progress' => count($matchedStages) . '/' . count($stages),
            'severity' => $topChain['severity'],
            'confidence' => $topChain['confidence'],
        ];
    }

    /**
     * Match events against a chain pattern.
     */
    private function matchPattern(array $events, array $pattern): ?array
    {
        $stages = $pattern['stages'];
        $guardMapping = $pattern['guards'];
        $maxGap = $pattern['max_stage_gap_seconds'];

        $matchedStages = [];
        $matchedEvents = [];
        $lastEventTime = null;
        $currentStageIndex = 0;

        // Sort events by timestamp
        usort($events, fn($a, $b) => $a['timestamp'] <=> $b['timestamp']);

        foreach ($events as $event) {
            if ($currentStageIndex >= count($stages)) {
                break;
            }

            $currentStage = $stages[$currentStageIndex];
            $stageGuards = $guardMapping[$currentStage] ?? [];

            // Check if event matches current stage
            if (in_array($event['guard'], $stageGuards)) {
                // Check time gap
                if ($lastEventTime !== null) {
                    $gap = $event['timestamp'] - $lastEventTime;
                    if ($gap > $maxGap) {
                        // Gap too large, reset chain matching
                        $matchedStages = [];
                        $matchedEvents = [];
                        $currentStageIndex = 0;
                        continue;
                    }
                }

                $matchedStages[] = $currentStage;
                $matchedEvents[] = $event;
                $lastEventTime = $event['timestamp'];
                $currentStageIndex++;
            }
        }

        // Require at least 2 stages matched
        if (count($matchedStages) < 2) {
            return null;
        }

        // Calculate confidence based on stages matched
        $confidence = count($matchedStages) / count($stages);

        return [
            'events' => $matchedEvents,
            'stages_matched' => $matchedStages,
            'confidence' => round($confidence, 2),
        ];
    }

    /**
     * Get relevant events for analysis.
     */
    private function getRelevantEvents(?string $ip, ?string $userId): array
    {
        $cutoff = time() - ($this->windowMinutes * 60);
        $events = [];

        // Get from buffer
        $bufferEvents = $this->eventBuffer->filter(function ($event) use ($cutoff, $ip, $userId) {
            if ($event['timestamp'] < $cutoff) {
                return false;
            }

            if ($ip !== null && $event['ip'] !== $ip) {
                return false;
            }

            if ($userId !== null && $event['user_id'] !== $userId) {
                return false;
            }

            return true;
        });

        $events = array_merge($events, $bufferEvents);

        // Get from cache
        if ($this->cache) {
            if ($ip) {
                $cached = $this->cache->get($this->cachePrefix . 'ip:' . md5($ip), []);
                $events = array_merge($events, array_filter(
                    $cached,
                    fn($e) => $e['timestamp'] >= $cutoff
                ));
            }

            if ($userId) {
                $cached = $this->cache->get($this->cachePrefix . 'user:' . $userId, []);
                $events = array_merge($events, array_filter(
                    $cached,
                    fn($e) => $e['timestamp'] >= $cutoff
                ));
            }
        }

        // Deduplicate
        $unique = [];
        foreach ($events as $event) {
            $key = $event['timestamp'] . '-' . $event['guard'] . '-' . ($event['ip'] ?? '');
            $unique[$key] = $event;
        }

        return array_values($unique);
    }

    /**
     * Store event for IP correlation.
     */
    private function storeEventForIp(string $ip, array $event): void
    {
        $key = $this->cachePrefix . 'ip:' . md5($ip);
        $events = $this->cache->get($key, []);
        $events[] = $event;

        // Keep last 50 events
        $events = array_slice($events, -50);

        $this->cache->set($key, $events, $this->windowMinutes * 60 * 2);
    }

    /**
     * Store event for user correlation.
     */
    private function storeEventForUser(string $userId, array $event): void
    {
        $key = $this->cachePrefix . 'user:' . $userId;
        $events = $this->cache->get($key, []);
        $events[] = $event;

        // Keep last 50 events
        $events = array_slice($events, -50);

        $this->cache->set($key, $events, $this->windowMinutes * 60 * 2);
    }

    /**
     * Build human-readable timeline.
     */
    private function buildTimeline(array $events): array
    {
        return array_map(function ($event) {
            return [
                'time' => date('Y-m-d H:i:s', $event['timestamp']),
                'guard' => $event['guard'],
                'path' => $event['path'] ?? null,
                'threat_level' => $event['threat_level'],
            ];
        }, $events);
    }

    /**
     * Add custom chain pattern.
     */
    public function addPattern(string $name, array $pattern): self
    {
        $this->chainPatterns[$name] = $pattern;
        return $this;
    }

    /**
     * Get statistics.
     */
    public function getStats(): array
    {
        return [
            'buffer_size' => $this->eventBuffer->count(),
            'buffer_capacity' => $this->eventBuffer->capacity(),
            'patterns_count' => count($this->chainPatterns),
            'window_minutes' => $this->windowMinutes,
        ];
    }

    /**
     * Clear event buffer.
     */
    public function clear(): void
    {
        $this->eventBuffer->clear();
    }
}
