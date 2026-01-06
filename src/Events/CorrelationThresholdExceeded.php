<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use M9nx\RuntimeGuard\Support\InspectionContext;

/**
 * Event fired when correlation threshold is exceeded.
 */
class CorrelationThresholdExceeded
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly string $identifier,
        public readonly string $identifierType,
        public readonly int $eventCount,
        public readonly int $threshold,
        public readonly int $windowSeconds,
        public readonly InspectionContext $context,
    ) {}

    /**
     * Get a description of the correlation event.
     */
    public function getDescription(): string
    {
        return sprintf(
            '%s "%s" exceeded threshold: %d events in %d seconds (threshold: %d)',
            ucfirst($this->identifierType),
            $this->identifier,
            $this->eventCount,
            $this->windowSeconds,
            $this->threshold
        );
    }

    /**
     * Convert to array for logging/serialization.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'identifier' => $this->identifier,
            'identifier_type' => $this->identifierType,
            'event_count' => $this->eventCount,
            'threshold' => $this->threshold,
            'window_seconds' => $this->windowSeconds,
            'description' => $this->getDescription(),
            'timestamp' => now()->toIso8601String(),
        ];
    }
}
