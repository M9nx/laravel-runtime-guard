<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Correlation;

use M9nx\RuntimeGuard\Contracts\ResponseMode;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;
use M9nx\RuntimeGuard\Support\InspectionContext;

/**
 * Handles progressive enforcement - escalating response over repeated events.
 *
 * Same threat escalates response over time: log → alert → block
 */
class ProgressiveEnforcement
{
    /**
     * @var array<string, array<int, int>>
     *
     * Structure: [key => [timestamp => count]]
     */
    private array $occurrences = [];

    /**
     * @param  array<int, string>  $stages
     */
    public function __construct(
        private readonly bool $enabled = false,
        private readonly array $stages = [
            1 => 'log',
            3 => 'alert',
            5 => 'block',
        ],
        private readonly int $windowSeconds = 3600,
        private readonly string $groupBy = 'ip',
    ) {}

    /**
     * Create from configuration array.
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            enabled: $config['enabled'] ?? false,
            stages: $config['stages'] ?? [1 => 'log', 3 => 'alert', 5 => 'block'],
            windowSeconds: $config['window'] ?? 3600,
            groupBy: $config['group_by'] ?? 'ip',
        );
    }

    /**
     * Record an occurrence and determine response mode.
     */
    public function recordAndDetermineResponse(
        InspectionContext $context,
        ThreatLevel $level,
        string $guardName
    ): ResponseMode {
        if (! $this->enabled) {
            return ResponseMode::LOG;
        }

        $key = $this->buildKey($context, $guardName);
        $this->recordOccurrence($key);
        $this->cleanExpired($key);

        $count = $this->getOccurrenceCount($key);

        return $this->determineResponseMode($count);
    }

    /**
     * Get current occurrence count for context.
     */
    public function getCount(InspectionContext $context, string $guardName): int
    {
        $key = $this->buildKey($context, $guardName);
        $this->cleanExpired($key);

        return $this->getOccurrenceCount($key);
    }

    /**
     * Determine response mode for an occurrence count.
     */
    public function determineResponseMode(int $count): ResponseMode
    {
        $applicableStage = 'log';

        // Sort stages by count threshold (ascending)
        $sortedStages = $this->stages;
        ksort($sortedStages);

        foreach ($sortedStages as $threshold => $mode) {
            if ($count >= $threshold) {
                $applicableStage = $mode;
            }
        }

        return ResponseMode::tryFrom($applicableStage) ?? ResponseMode::LOG;
    }

    /**
     * Check if blocking should occur at current count.
     */
    public function shouldBlock(InspectionContext $context, string $guardName): bool
    {
        $count = $this->getCount($context, $guardName);
        $mode = $this->determineResponseMode($count);

        return $mode === ResponseMode::BLOCK;
    }

    /**
     * Clear all occurrences.
     */
    public function flush(): void
    {
        $this->occurrences = [];
    }

    /**
     * Clear occurrences for a specific context.
     */
    public function clearFor(InspectionContext $context, string $guardName): void
    {
        $key = $this->buildKey($context, $guardName);
        unset($this->occurrences[$key]);
    }

    /**
     * Get statistics.
     *
     * @return array{keys: int, enabled: bool}
     */
    public function stats(): array
    {
        return [
            'keys' => count($this->occurrences),
            'enabled' => $this->enabled,
        ];
    }

    /**
     * Build unique key for tracking.
     */
    private function buildKey(InspectionContext $context, string $guardName): string
    {
        return $guardName . ':' . $context->correlationKey($this->groupBy);
    }

    /**
     * Record a single occurrence.
     */
    private function recordOccurrence(string $key): void
    {
        if (! isset($this->occurrences[$key])) {
            $this->occurrences[$key] = [];
        }

        $this->occurrences[$key][] = time();
    }

    /**
     * Get occurrence count for a key.
     */
    private function getOccurrenceCount(string $key): int
    {
        return count($this->occurrences[$key] ?? []);
    }

    /**
     * Clean expired occurrences.
     */
    private function cleanExpired(string $key): void
    {
        if (! isset($this->occurrences[$key])) {
            return;
        }

        $cutoff = time() - $this->windowSeconds;

        $this->occurrences[$key] = array_filter(
            $this->occurrences[$key],
            fn (int $timestamp) => $timestamp >= $cutoff
        );

        if (empty($this->occurrences[$key])) {
            unset($this->occurrences[$key]);
        }
    }
}
