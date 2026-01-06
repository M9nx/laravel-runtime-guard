<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Attributes;

use Attribute;

/**
 * Assign a guard profile to a controller or method.
 *
 * @example
 * #[GuardProfile('strict')]
 * class AuthController extends Controller {}
 *
 * #[GuardProfile('relaxed')]
 * public function webhook() {}
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class GuardProfile
{
    public function __construct(
        public string $profile,
    ) {}
}
