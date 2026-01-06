<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Attributes;

use Attribute;

/**
 * Skip RuntimeGuard inspection for a controller or method.
 *
 * @example
 * #[SkipGuard]
 * public function healthCheck() {}
 *
 * #[SkipGuard(['sql-injection', 'xss'])]
 * public function webhook() {}
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class SkipGuard
{
    /**
     * @param  array<string>|null  $guards  Specific guards to skip, or null for all
     */
    public function __construct(
        public ?array $guards = null,
    ) {}

    /**
     * Check if all guards should be skipped.
     */
    public function skipsAll(): bool
    {
        return $this->guards === null;
    }

    /**
     * Check if a specific guard should be skipped.
     */
    public function skips(string $guardName): bool
    {
        if ($this->guards === null) {
            return true;
        }

        return in_array($guardName, $this->guards, true);
    }
}
