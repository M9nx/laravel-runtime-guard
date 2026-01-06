<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Facades;

use Illuminate\Support\Facades\Facade;
use M9nx\RuntimeGuard\Contracts\GuardInterface;
use M9nx\RuntimeGuard\Contracts\GuardManagerInterface;
use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Pipeline\PipelineResult;
use M9nx\RuntimeGuard\Support\InspectionContext;
use M9nx\RuntimeGuard\Testing\RuntimeGuardFake;

/**
 * @method static \M9nx\RuntimeGuard\GuardManager register(GuardInterface $guard)
 * @method static \M9nx\RuntimeGuard\GuardManager registerClass(string $guardClass)
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
 * @method static \M9nx\RuntimeGuard\FeatureFlags\FeatureFlagManager getFeatureFlags()
 * @method static \M9nx\RuntimeGuard\Correlation\CorrelationEngine|null getCorrelationEngine()
 * @method static \M9nx\RuntimeGuard\Correlation\ProgressiveEnforcement|null getProgressiveEnforcement()
 * @method static \M9nx\RuntimeGuard\Pipeline\GuardPipeline|null getPipeline()
 *
 * @see \M9nx\RuntimeGuard\GuardManager
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
