<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Facades;

use Illuminate\Support\Facades\Facade;
use Mounir\RuntimeGuard\Contracts\GuardInterface;
use Mounir\RuntimeGuard\Contracts\GuardManagerInterface;
use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Pipeline\PipelineResult;
use Mounir\RuntimeGuard\Support\InspectionContext;
use Mounir\RuntimeGuard\Testing\RuntimeGuardFake;

/**
 * @method static \Mounir\RuntimeGuard\GuardManager register(GuardInterface $guard)
 * @method static \Mounir\RuntimeGuard\GuardManager registerClass(string $guardClass)
 * @method static GuardInterface|null get(string $name)
 * @method static bool has(string $name)
 * @method static array<string, GuardInterface> all()
 * @method static array<GuardInterface> enabled()
 * @method static array<GuardResultInterface> inspect(mixed $input, array $context = [])
 * @method static PipelineResult inspectWithContext(mixed $input, InspectionContext $context, ?string $profileName = null)
 * @method static GuardResultInterface inspectWith(string $guardName, mixed $input, array $context = [])
 * @method static bool isEnabled()
 * @method static array getConfig()
 * @method static array getStats()
 * @method static \Mounir\RuntimeGuard\FeatureFlags\FeatureFlagManager getFeatureFlags()
 * @method static \Mounir\RuntimeGuard\Correlation\CorrelationEngine|null getCorrelationEngine()
 * @method static \Mounir\RuntimeGuard\Correlation\ProgressiveEnforcement|null getProgressiveEnforcement()
 * @method static \Mounir\RuntimeGuard\Pipeline\GuardPipeline|null getPipeline()
 *
 * @see \Mounir\RuntimeGuard\GuardManager
 */
class RuntimeGuard extends Facade
{
    /**
     * Replace the bound instance with a fake for testing.
     */
    public static function fake(): RuntimeGuardFake
    {
        static::swap($fake = new RuntimeGuardFake());

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return GuardManagerInterface::class;
    }
}
