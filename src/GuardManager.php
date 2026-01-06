<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard;

use M9nx\RuntimeGuard\Contracts\BootableGuard;
use M9nx\RuntimeGuard\Contracts\GuardInterface;
use M9nx\RuntimeGuard\Contracts\GuardManagerInterface;
use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ReporterInterface;
use M9nx\RuntimeGuard\Contracts\ResponseMode;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;
use M9nx\RuntimeGuard\Correlation\CorrelationEngine;
use M9nx\RuntimeGuard\Correlation\ProgressiveEnforcement;
use M9nx\RuntimeGuard\Exceptions\GuardNotFoundException;
use M9nx\RuntimeGuard\FeatureFlags\FeatureFlagManager;
use M9nx\RuntimeGuard\Pipeline\GuardPipeline;
use M9nx\RuntimeGuard\Pipeline\PipelineResult;
use M9nx\RuntimeGuard\Profiles\GuardProfile;
use M9nx\RuntimeGuard\Profiles\ProfileResolver;
use M9nx\RuntimeGuard\Support\DeduplicationCache;
use M9nx\RuntimeGuard\Support\InputLimiter;
use M9nx\RuntimeGuard\Support\InspectionContext;
use M9nx\RuntimeGuard\Support\SamplingDecider;
use Illuminate\Contracts\Container\Container;

/**
 * Central registry and orchestrator for all guards.
 */
class GuardManager implements GuardManagerInterface
{
    /**
     * Resolved guard instances.
     *
     * @var array<string, GuardInterface>
     */
    protected array $guards = [];

    /**
     * Guard class names for lazy loading.
     *
     * @var array<string, class-string<GuardInterface>>
     */
    protected array $guardClasses = [];

    /**
     * Configuration array.
     *
     * @var array<string, mixed>
     */
    protected array $config = [];

    protected ?GuardPipeline $pipeline = null;

    protected ?DeduplicationCache $deduplicationCache = null;

    protected ?SamplingDecider $samplingDecider = null;

    protected ?InputLimiter $inputLimiter = null;

    protected ?CorrelationEngine $correlationEngine = null;

    protected ?ProgressiveEnforcement $progressiveEnforcement = null;

    protected ?ProfileResolver $profileResolver = null;

    protected ?FeatureFlagManager $featureFlags = null;

    /**
     * @var array<ReporterInterface>
     */
    protected array $reporters = [];

    /**
     * Track already inspected hashes within request.
     *
     * @var array<string, bool>
     */
    protected array $inspectedHashes = [];

    /**
     * Before inspection callbacks.
     *
     * @var array<callable>
     */
    protected array $beforeCallbacks = [];

    /**
     * After inspection callbacks.
     *
     * @var array<callable>
     */
    protected array $afterCallbacks = [];

    public function __construct(
        protected Container $container,
    ) {}

    /**
     * Boot the manager with configuration.
     */
    public function boot(array $config): void
    {
        $this->config = $config;

        $this->initializePipeline();
        $this->initializePerformanceComponents();
        $this->initializeAdvancedFeatures();

        foreach ($this->all() as $guard) {
            if ($guard instanceof BootableGuard && ! $guard->isBooted()) {
                $guard->boot();
            }
        }
    }

    /**
     * Initialize pipeline configuration.
     */
    protected function initializePipeline(): void
    {
        $this->pipeline = GuardPipeline::fromConfig(
            $this->config['pipeline'] ?? []
        );
    }

    /**
     * Initialize performance components.
     */
    protected function initializePerformanceComponents(): void
    {
        $perfConfig = $this->config['performance'] ?? [];

        if ($perfConfig['deduplication']['enabled'] ?? false) {
            $this->deduplicationCache = new DeduplicationCache(
                maxEntries: $perfConfig['deduplication']['max_entries'] ?? 1000,
                ttlSeconds: $perfConfig['deduplication']['ttl'] ?? 60,
            );
        }

        $this->samplingDecider = SamplingDecider::fromConfig(
            $perfConfig['sampling'] ?? []
        );

        $limits = $perfConfig['limits'] ?? [];
        $this->inputLimiter = new InputLimiter(
            maxBytes: $limits['max_input_bytes'] ?? 65536,
            maxArrayDepth: $limits['max_array_depth'] ?? 10,
            maxArrayItems: $limits['max_array_items'] ?? 1000,
        );
    }

    /**
     * Initialize advanced feature components.
     */
    protected function initializeAdvancedFeatures(): void
    {
        $this->correlationEngine = CorrelationEngine::fromConfig(
            $this->config['correlation'] ?? []
        );

        $this->progressiveEnforcement = ProgressiveEnforcement::fromConfig(
            $this->config['progressive'] ?? []
        );

        $this->profileResolver = ProfileResolver::fromConfig($this->config);

        $this->featureFlags = FeatureFlagManager::fromConfig(
            $this->config['feature_flags'] ?? [],
            $this->container->bound('cache') ? $this->container->make('cache') : null
        );
    }

    public function register(GuardInterface $guard): static
    {
        $this->guards[$guard->getName()] = $guard;

        return $this;
    }

    public function registerClass(string $guardClass): static
    {
        $this->guardClasses[$guardClass] = $guardClass;

        return $this;
    }

    /**
     * Register a reporter.
     */
    public function registerReporter(ReporterInterface $reporter): static
    {
        $this->reporters[] = $reporter;

        return $this;
    }

    public function get(string $name): ?GuardInterface
    {
        if (isset($this->guards[$name])) {
            return $this->guards[$name];
        }

        foreach ($this->guardClasses as $key => $guardClass) {
            if (! isset($this->guards[$key])) {
                $guard = $this->resolveGuard($guardClass);
                $this->guards[$guard->getName()] = $guard;
                unset($this->guardClasses[$key]);

                if ($guard->getName() === $name) {
                    return $guard;
                }
            }
        }

        return $this->guards[$name] ?? null;
    }

    public function has(string $name): bool
    {
        return $this->get($name) !== null;
    }

    public function all(): array
    {
        foreach ($this->guardClasses as $guardClass) {
            $guard = $this->resolveGuard($guardClass);
            $this->guards[$guard->getName()] = $guard;
        }
        $this->guardClasses = [];

        return $this->guards;
    }

    public function enabled(): array
    {
        $guards = array_filter(
            $this->all(),
            fn (GuardInterface $guard) => $this->isGuardEnabled($guard)
        );

        uasort($guards, fn (GuardInterface $a, GuardInterface $b) => $b->getPriority() <=> $a->getPriority());

        return array_values($guards);
    }

    /**
     * Check if a guard is enabled (considering feature flags).
     */
    protected function isGuardEnabled(GuardInterface $guard): bool
    {
        if (! $guard->isEnabled()) {
            return false;
        }

        if ($this->featureFlags) {
            return $this->featureFlags->isEnabled($guard->getName(), true);
        }

        return true;
    }

    public function inspect(mixed $input, array $context = []): array
    {
        $inspectionContext = InspectionContext::forInput($input, $context);

        return $this->inspectWithContext($input, $inspectionContext)->getResults();
    }

    /**
     * Inspect with full context support.
     */
    public function inspectWithContext(
        mixed $input,
        InspectionContext $context,
        ?string $profileName = null
    ): PipelineResult {
        if (! $this->isEnabled()) {
            return new PipelineResult([], 0, 0, 0);
        }

        if ($this->samplingDecider && ! $this->samplingDecider->shouldInspect($context)) {
            return new PipelineResult([], 0, 0, count($this->enabled()));
        }

        $hash = $context->inputHash();
        if ($hash && $this->deduplicationCache) {
            $cached = $this->deduplicationCache->get($hash);
            if ($cached !== null) {
                return new PipelineResult([$cached], 0, 0, count($this->enabled()));
            }
        }

        if ($hash && isset($this->inspectedHashes[$hash])) {
            return new PipelineResult([], 0, 0, count($this->enabled()));
        }

        if ($this->inputLimiter) {
            $input = $this->inputLimiter->limit($input);
        }

        $profile = $this->resolveProfile($profileName, $context);
        $guards = $this->getGuardsForProfile($profile);
        $results = $this->pipeline->execute($guards, $input, $context);

        foreach ($results as $result) {
            if ($this->correlationEngine && $result->failed()) {
                $this->correlationEngine->recordAndEvaluate($result, $context);
            }

            $this->report($result, $context);
        }

        if ($hash && $this->deduplicationCache) {
            foreach ($results as $result) {
                if ($result->failed()) {
                    $this->deduplicationCache->put($hash, $result);
                    break;
                }
            }
        }

        if ($hash) {
            $this->inspectedHashes[$hash] = true;
        }

        return new PipelineResult(
            $results,
            $this->pipeline->getLastExecutionTimeMs(),
            $this->pipeline->getGuardsExecuted(),
            $this->pipeline->getGuardsSkipped()
        );
    }

    public function inspectWith(string $guardName, mixed $input, array $context = []): GuardResultInterface
    {
        $guard = $this->get($guardName);

        if ($guard === null) {
            throw GuardNotFoundException::forName($guardName);
        }

        return $guard->inspect($input, $context);
    }

    /**
     * Report a result to all reporters.
     */
    public function report(GuardResultInterface $result, InspectionContext $context): void
    {
        if ($result->passed()) {
            return;
        }

        foreach ($this->reporters as $reporter) {
            if ($reporter->shouldReport($result)) {
                $reporter->report($result, $context->toArray());
            }
        }
    }

    /**
     * Check if the manager is globally enabled.
     */
    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? true;
    }

    /**
     * Get response mode.
     */
    public function getResponseMode(): ResponseMode
    {
        if ($this->config['dry_run'] ?? false) {
            return ResponseMode::DRY_RUN;
        }

        return ResponseMode::tryFrom($this->config['mode'] ?? 'log') ?? ResponseMode::LOG;
    }

    /**
     * Check if context should be excluded.
     */
    public function shouldExclude(InspectionContext $context): bool
    {
        $exclusions = $this->config['exclusions'] ?? [];

        foreach ($exclusions['paths'] ?? [] as $pattern) {
            if ($context->pathMatches($pattern)) {
                return true;
            }
        }

        $routeName = $context->routeName();
        if ($routeName && in_array($routeName, $exclusions['routes'] ?? [], true)) {
            return true;
        }

        $ip = $context->ip();
        if ($ip && in_array($ip, $exclusions['ips'] ?? [], true)) {
            return true;
        }

        return false;
    }

    /**
     * Get configuration.
     *
     * @return array<string, mixed>
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Get feature flag manager.
     */
    public function getFeatureFlags(): FeatureFlagManager
    {
        if (! $this->featureFlags) {
            $this->featureFlags = new FeatureFlagManager();
        }

        return $this->featureFlags;
    }

    /**
     * Get correlation engine.
     */
    public function getCorrelationEngine(): ?CorrelationEngine
    {
        return $this->correlationEngine;
    }

    /**
     * Get progressive enforcement.
     */
    public function getProgressiveEnforcement(): ?ProgressiveEnforcement
    {
        return $this->progressiveEnforcement;
    }

    /**
     * Get pipeline.
     */
    public function getPipeline(): ?GuardPipeline
    {
        return $this->pipeline;
    }

    /**
     * Resolve a guard from class name.
     */
    protected function resolveGuard(string $guardClass): GuardInterface
    {
        return $this->container->make($guardClass);
    }

    /**
     * Resolve profile for inspection.
     */
    protected function resolveProfile(?string $profileName, InspectionContext $context): ?GuardProfile
    {
        if ($profileName && $this->profileResolver) {
            return $this->profileResolver->getProfile($profileName);
        }

        return $this->profileResolver?->resolve($context);
    }

    /**
     * Get guards applicable for a profile.
     *
     * @return array<GuardInterface>
     */
    protected function getGuardsForProfile(?GuardProfile $profile): array
    {
        $guards = $this->enabled();

        if (! $profile) {
            return $guards;
        }

        return array_filter(
            $guards,
            fn (GuardInterface $guard) => $profile->includesGuard($guard->getName())
        );
    }

    /**
     * Clear request-level state.
     */
    public function clearRequestState(): void
    {
        $this->inspectedHashes = [];
    }

    /**
     * Get registered guard names.
     *
     * @return array<string>
     */
    public function getRegisteredNames(): array
    {
        return array_keys($this->all());
    }

    /**
     * Get statistics.
     *
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        return [
            'guards_total' => count($this->all()),
            'guards_enabled' => count($this->enabled()),
            'deduplication' => $this->deduplicationCache?->stats(),
            'correlation' => $this->correlationEngine?->stats(),
            'progressive' => $this->progressiveEnforcement?->stats(),
            'pipeline' => $this->pipeline?->getStats(),
        ];
    }

    /**
     * Register a callback to run before each guard inspection.
     */
    public function beforeInspection(callable $callback): static
    {
        $this->beforeCallbacks[] = $callback;

        return $this;
    }

    /**
     * Register a callback to run after each guard inspection.
     */
    public function afterInspection(callable $callback): static
    {
        $this->afterCallbacks[] = $callback;

        return $this;
    }

    /**
     * Execute before inspection callbacks.
     */
    public function fireBeforeInspection(GuardInterface $guard, mixed $input, InspectionContext $context): void
    {
        foreach ($this->beforeCallbacks as $callback) {
            $callback($guard, $input, $context);
        }
    }

    /**
     * Execute after inspection callbacks.
     */
    public function fireAfterInspection(GuardInterface $guard, GuardResultInterface $result, float $duration): void
    {
        foreach ($this->afterCallbacks as $callback) {
            $callback($guard, $result, $duration);
        }
    }
}
