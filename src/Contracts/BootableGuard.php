<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Contracts;

/**
 * Guards that can boot/initialize on service provider boot.
 *
 * Bootable guards can perform one-time initialization such as
 * compiling regex patterns, loading configuration, etc.
 */
interface BootableGuard extends GuardInterface
{
    /**
     * Boot the guard.
     *
     * Called once during service provider boot phase.
     * Use for pattern compilation, config loading, etc.
     */
    public function boot(): void;

    /**
     * Check if the guard has been booted.
     */
    public function isBooted(): bool;
}
