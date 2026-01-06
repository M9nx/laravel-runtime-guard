<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Contracts;

use Mounir\RuntimeGuard\Support\InspectionContext;

/**
 * Guards that support threat correlation.
 *
 * Correlation-aware guards provide keys that allow the correlation
 * engine to group and escalate related security events.
 */
interface CorrelationAware
{
    /**
     * Get the correlation key for grouping related events.
     *
     * Events with the same correlation key from the same source
     * will be analyzed together for pattern detection.
     */
    public function getCorrelationKey(InspectionContext $context): string;

    /**
     * Get the correlation group (e.g., 'ip', 'user', 'session').
     */
    public function getCorrelationGroup(): string;
}
