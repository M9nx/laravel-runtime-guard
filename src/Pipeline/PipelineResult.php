<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Pipeline;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Aggregates multiple guard results into a summary.
 */
final readonly class PipelineResult
{
    /**
     * @param  array<GuardResultInterface>  $results
     */
    public function __construct(
        private array $results,
        private float $durationMs,
        private int $guardsExecuted,
        private int $guardsSkipped,
    ) {}

    /**
     * Check if all guards passed.
     */
    public function allPassed(): bool
    {
        foreach ($this->results as $result) {
            if ($result->failed()) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if any guard failed.
     */
    public function hasFailed(): bool
    {
        return ! $this->allPassed();
    }

    /**
     * Get the highest threat level detected.
     */
    public function getHighestThreatLevel(): ThreatLevel
    {
        $highest = ThreatLevel::NONE;

        foreach ($this->results as $result) {
            if ($result->getThreatLevel()->weight() > $highest->weight()) {
                $highest = $result->getThreatLevel();
            }
        }

        return $highest;
    }

    /**
     * Get all failed results.
     *
     * @return array<GuardResultInterface>
     */
    public function getFailedResults(): array
    {
        return array_filter(
            $this->results,
            fn (GuardResultInterface $result) => $result->failed()
        );
    }

    /**
     * Get results at or above a threat level.
     *
     * @return array<GuardResultInterface>
     */
    public function getResultsAtOrAbove(ThreatLevel $level): array
    {
        return array_filter(
            $this->results,
            fn (GuardResultInterface $result) => $result->getThreatLevel()->weight() >= $level->weight()
        );
    }

    /**
     * Get all results.
     *
     * @return array<GuardResultInterface>
     */
    public function getResults(): array
    {
        return $this->results;
    }

    /**
     * Get result count.
     */
    public function count(): int
    {
        return count($this->results);
    }

    /**
     * Get execution duration in milliseconds.
     */
    public function getDurationMs(): float
    {
        return $this->durationMs;
    }

    /**
     * Get number of guards executed.
     */
    public function getGuardsExecuted(): int
    {
        return $this->guardsExecuted;
    }

    /**
     * Get number of guards skipped.
     */
    public function getGuardsSkipped(): int
    {
        return $this->guardsSkipped;
    }

    /**
     * Convert to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'passed' => $this->allPassed(),
            'highest_threat_level' => $this->getHighestThreatLevel()->value,
            'duration_ms' => $this->durationMs,
            'guards_executed' => $this->guardsExecuted,
            'guards_skipped' => $this->guardsSkipped,
            'results' => array_map(
                fn (GuardResultInterface $r) => $r instanceof \M9nx\RuntimeGuard\Support\GuardResult
                    ? $r->toArray()
                    : [
                        'guard' => $r->getGuardName(),
                        'passed' => $r->passed(),
                        'threat_level' => $r->getThreatLevel()->value,
                        'message' => $r->getMessage(),
                    ],
                $this->results
            ),
        ];
    }
}
