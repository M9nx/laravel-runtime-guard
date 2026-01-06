<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Contracts;

/**
 * Represents the result of a guard inspection.
 */
interface GuardResultInterface
{
    /**
     * Determine if the inspection passed (no threat detected).
     */
    public function passed(): bool;

    /**
     * Determine if the inspection failed (threat detected).
     */
    public function failed(): bool;

    /**
     * Get the threat level if a threat was detected.
     */
    public function getThreatLevel(): ThreatLevel;

    /**
     * Get a human-readable message describing the result.
     */
    public function getMessage(): string;

    /**
     * Get additional metadata about the inspection.
     *
     * @return array<string, mixed>
     */
    public function getMetadata(): array;

    /**
     * Get the name of the guard that produced this result.
     */
    public function getGuardName(): string;
}
