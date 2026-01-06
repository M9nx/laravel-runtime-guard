<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Contracts;

/**
 * Core interface that all guards must implement.
 *
 * Guards are responsible for inspecting input and determining
 * whether it poses a security threat.
 */
interface GuardInterface
{
    /**
     * Get the unique identifier for this guard.
     */
    public function getName(): string;

    /**
     * Inspect the given input for potential security threats.
     *
     * @param  mixed  $input  The input to inspect (string, array, etc.)
     * @param  array<string, mixed>  $context  Additional context for inspection
     */
    public function inspect(mixed $input, array $context = []): GuardResultInterface;

    /**
     * Determine if this guard is enabled.
     */
    public function isEnabled(): bool;

    /**
     * Get the priority of this guard (higher = runs first).
     */
    public function getPriority(): int;
}
