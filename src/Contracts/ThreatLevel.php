<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Contracts;

/**
 * Enum representing the severity level of a detected threat.
 */
enum ThreatLevel: string
{
    case NONE = 'none';
    case LOW = 'low';
    case MEDIUM = 'medium';
    case HIGH = 'high';
    case CRITICAL = 'critical';

    /**
     * Determine if this threat level should trigger blocking.
     */
    public function shouldBlock(): bool
    {
        return match ($this) {
            self::HIGH, self::CRITICAL => true,
            default => false,
        };
    }

    /**
     * Determine if this threat level should be logged.
     */
    public function shouldLog(): bool
    {
        return $this !== self::NONE;
    }

    /**
     * Get numeric weight for comparison.
     */
    public function weight(): int
    {
        return match ($this) {
            self::NONE => 0,
            self::LOW => 1,
            self::MEDIUM => 2,
            self::HIGH => 3,
            self::CRITICAL => 4,
        };
    }
}
