<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Contracts;

/**
 * Enum representing pipeline execution strategies.
 */
enum PipelineStrategy: string
{
    /**
     * Run all guards regardless of results.
     */
    case FULL = 'full';

    /**
     * Stop execution when a threat at or above threshold is detected.
     */
    case SHORT_CIRCUIT = 'short_circuit';

    /**
     * Stop when cumulative threat score exceeds threshold.
     */
    case THRESHOLD = 'threshold';
}
