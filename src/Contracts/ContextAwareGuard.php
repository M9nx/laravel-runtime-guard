<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Contracts;

use M9nx\RuntimeGuard\Support\InspectionContext;

/**
 * Guards that implement context-aware inspection.
 *
 * Context-aware guards can decide whether they apply to a given
 * inspection context before performing the actual inspection.
 */
interface ContextAwareGuard extends GuardInterface
{
    /**
     * Determine if this guard applies to the given context.
     *
     * Return false to skip this guard entirely for this context.
     */
    public function appliesTo(InspectionContext $context): bool;
}
