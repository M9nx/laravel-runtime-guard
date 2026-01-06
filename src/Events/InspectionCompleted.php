<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Mounir\RuntimeGuard\Pipeline\PipelineResult;
use Mounir\RuntimeGuard\Support\InspectionContext;

/**
 * Event fired when an inspection is completed.
 */
class InspectionCompleted
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly PipelineResult $result,
        public readonly InspectionContext $context,
        public readonly float $durationMs,
    ) {}

    /**
     * Check if any threats were detected.
     */
    public function hasThreat(): bool
    {
        return $this->result->hasThreat();
    }

    /**
     * Get number of guards executed.
     */
    public function getGuardsExecuted(): int
    {
        return $this->result->guardsExecuted;
    }

    /**
     * Get execution duration in milliseconds.
     */
    public function getDurationMs(): float
    {
        return $this->durationMs;
    }

    /**
     * Convert to array for logging/serialization.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'has_threat' => $this->hasThreat(),
            'guards_executed' => $this->getGuardsExecuted(),
            'guards_skipped' => $this->result->guardsSkipped,
            'duration_ms' => $this->durationMs,
            'context' => [
                'path' => $this->context->path(),
                'method' => $this->context->method(),
                'ip' => $this->context->ip(),
            ],
        ];
    }
}
