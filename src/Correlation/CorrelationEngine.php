<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Correlation;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;
use Mounir\RuntimeGuard\Support\InspectionContext;

/**
 * Correlates multiple security events to detect coordinated attacks.
 *
 * When multiple low-severity events occur from the same source within
 * a time window, the correlation engine can escalate the threat level.
 */
class CorrelationEngine
{
    /**
     * @var array<string, array<int, array{level: ThreatLevel, timestamp: int, guard: string}>>
     */
    private array $events = [];

    /**
     * @param  array<array{count: int, source_level: string, target_level: string}>  $rules
     * @param  array<string>  $groupBy
     */
    public function __construct(
        private readonly bool $enabled = false,
        private readonly int $windowSeconds = 60,
        private readonly array $rules = [],
        private readonly array $groupBy = ['ip'],
        private readonly int $maxEventsPerKey = 100,
    ) {}

    /**
     * Create from configuration array.
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            enabled: $config['enabled'] ?? false,
            windowSeconds: $config['window'] ?? 60,
            rules: $config['rules'] ?? [],
            groupBy: $config['group_by'] ?? ['ip'],
            maxEventsPerKey: $config['max_events_per_key'] ?? 100,
        );
    }

    /**
     * Record an event and check for escalation.
     */
    public function recordAndEvaluate(
        GuardResultInterface $result,
        InspectionContext $context
    ): ?ThreatLevel {
        if (! $this->enabled || $result->passed()) {
            return null;
        }

        $key = $this->buildCorrelationKey($context);
        $this->recordEvent($key, $result);
        $this->cleanExpiredEvents($key);

        return $this->evaluateEscalation($key, $result->getThreatLevel());
    }

    /**
     * Record an event without evaluation.
     */
    public function record(GuardResultInterface $result, InspectionContext $context): void
    {
        if (! $this->enabled || $result->passed()) {
            return;
        }

        $key = $this->buildCorrelationKey($context);
        $this->recordEvent($key, $result);
    }

    /**
     * Evaluate if escalation should occur.
     */
    public function evaluate(InspectionContext $context): ?ThreatLevel
    {
        if (! $this->enabled) {
            return null;
        }

        $key = $this->buildCorrelationKey($context);
        $this->cleanExpiredEvents($key);

        $events = $this->events[$key] ?? [];
        if (empty($events)) {
            return null;
        }

        // Get the most common (or highest) level in current events
        $levelCounts = [];
        foreach ($events as $event) {
            $level = $event['level']->value;
            $levelCounts[$level] = ($levelCounts[$level] ?? 0) + 1;
        }

        foreach ($this->rules as $rule) {
            $sourceLevel = $rule['source_level'];
            $count = $levelCounts[$sourceLevel] ?? 0;

            if ($count >= $rule['count']) {
                return ThreatLevel::from($rule['target_level']);
            }
        }

        return null;
    }

    /**
     * Get event count for a context.
     */
    public function getEventCount(InspectionContext $context): int
    {
        $key = $this->buildCorrelationKey($context);
        $this->cleanExpiredEvents($key);

        return count($this->events[$key] ?? []);
    }

    /**
     * Get events for a context.
     *
     * @return array<array{level: ThreatLevel, timestamp: int, guard: string}>
     */
    public function getEvents(InspectionContext $context): array
    {
        $key = $this->buildCorrelationKey($context);
        $this->cleanExpiredEvents($key);

        return $this->events[$key] ?? [];
    }

    /**
     * Clear all recorded events.
     */
    public function flush(): void
    {
        $this->events = [];
    }

    /**
     * Clear events for a specific context.
     */
    public function clearFor(InspectionContext $context): void
    {
        $key = $this->buildCorrelationKey($context);
        unset($this->events[$key]);
    }

    /**
     * Build correlation key from context.
     */
    private function buildCorrelationKey(InspectionContext $context): string
    {
        $parts = [];

        foreach ($this->groupBy as $group) {
            $parts[] = $context->correlationKey($group);
        }

        return implode(':', $parts);
    }

    /**
     * Record a single event.
     */
    private function recordEvent(string $key, GuardResultInterface $result): void
    {
        if (! isset($this->events[$key])) {
            $this->events[$key] = [];
        }

        // Enforce max events per key
        if (count($this->events[$key]) >= $this->maxEventsPerKey) {
            array_shift($this->events[$key]);
        }

        $this->events[$key][] = [
            'level' => $result->getThreatLevel(),
            'timestamp' => time(),
            'guard' => $result->getGuardName(),
        ];
    }

    /**
     * Remove expired events.
     */
    private function cleanExpiredEvents(string $key): void
    {
        if (! isset($this->events[$key])) {
            return;
        }

        $cutoff = time() - $this->windowSeconds;

        $this->events[$key] = array_filter(
            $this->events[$key],
            fn (array $event) => $event['timestamp'] >= $cutoff
        );

        if (empty($this->events[$key])) {
            unset($this->events[$key]);
        }
    }

    /**
     * Evaluate escalation for a specific key and level.
     */
    private function evaluateEscalation(string $key, ThreatLevel $currentLevel): ?ThreatLevel
    {
        $events = $this->events[$key] ?? [];

        foreach ($this->rules as $rule) {
            $sourceLevel = ThreatLevel::from($rule['source_level']);
            $requiredCount = $rule['count'];

            // Count events at or above source level
            $matchingEvents = array_filter(
                $events,
                fn (array $event) => $event['level']->weight() >= $sourceLevel->weight()
            );

            if (count($matchingEvents) >= $requiredCount) {
                $targetLevel = ThreatLevel::from($rule['target_level']);

                // Only escalate if target is higher than current
                if ($targetLevel->weight() > $currentLevel->weight()) {
                    return $targetLevel;
                }
            }
        }

        return null;
    }

    /**
     * Get statistics about current state.
     *
     * @return array{keys: int, total_events: int, enabled: bool}
     */
    public function stats(): array
    {
        $totalEvents = 0;
        foreach ($this->events as $events) {
            $totalEvents += count($events);
        }

        return [
            'keys' => count($this->events),
            'total_events' => $totalEvents,
            'enabled' => $this->enabled,
        ];
    }
}
