<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Contracts;

/**
 * Interface for reporting detected threats.
 *
 * Reporters handle logging, alerting, and recording of security events.
 */
interface ReporterInterface
{
    /**
     * Report a guard result.
     */
    public function report(GuardResultInterface $result, array $context = []): void;

    /**
     * Determine if this reporter should handle the given result.
     */
    public function shouldReport(GuardResultInterface $result): bool;
}
