<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Exceptions;

/**
 * Exception thrown when a requested guard is not found.
 */
class GuardNotFoundException extends RuntimeGuardException
{
    public static function forName(string $name): self
    {
        return new self("Guard [{$name}] not found. Did you register it in the configuration?");
    }
}
