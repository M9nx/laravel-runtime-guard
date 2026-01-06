<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Performance;

use Mounir\RuntimeGuard\Contracts\GuardInterface;
use Mounir\RuntimeGuard\Context\RuntimeContext;
use Illuminate\Support\Facades\Cache;

/**
 * Guard Fusion Optimizer.
 *
 * Intelligently combines and optimizes guard execution:
 * - Merges redundant checks across guards
 * - Creates optimized execution plans
 * - Short-circuits when early termination is possible
 * - Caches intermediate results for reuse
 */
class GuardFusionOptimizer
{
    private array $config;
    private array $guards;
    private array $dependencyGraph;
    private array $fusionRules;
    private string $cachePrefix;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->guards = [];
        $this->dependencyGraph = [];
        $this->cachePrefix = $config['cache_prefix'] ?? 'guard_fusion:';

        $this->fusionRules = $config['fusion_rules'] ?? [
            // Groups of guards that can share computed data
            'input_parsing' => ['sql_injection', 'xss', 'payload_obfuscation'],
            'rate_analysis' => ['rate_limit', 'brute_force', 'credential_stuffing'],
            'session_analysis' => ['session_integrity', 'jwt', 'session_hijack'],
            'pattern_matching' => ['sql_injection', 'xss', 'path_traversal', 'command_injection'],
        ];
    }

    /**
     * Register guards for optimization.
     */
    public function registerGuards(array $guards): void
    {
        $this->guards = [];
        foreach ($guards as $guard) {
            if ($guard instanceof GuardInterface) {
                $this->guards[$guard->getName()] = $guard;
            }
        }

        $this->buildDependencyGraph();
    }

    /**
     * Create optimized execution plan.
     */
    public function createExecutionPlan(RuntimeContext $context): ExecutionPlan
    {
        $enabledGuards = array_filter($this->guards, fn($g) => $g->isEnabled());

        // Sort by priority
        uasort($enabledGuards, fn($a, $b) => $b->getPriority() <=> $a->getPriority());

        // Identify shared computation opportunities
        $sharedComputations = $this->identifySharedComputations($enabledGuards);

        // Create optimized stages
        $stages = $this->createStages($enabledGuards, $sharedComputations);

        // Add early termination points
        $stages = $this->addEarlyTerminationPoints($stages);

        return new ExecutionPlan($stages, $sharedComputations);
    }

    /**
     * Execute optimized plan.
     */
    public function execute(ExecutionPlan $plan, RuntimeContext $context): FusionResult
    {
        $results = [];
        $sharedData = [];
        $startTime = microtime(true);
        $guardsExecuted = 0;
        $guardsSkipped = 0;

        // Pre-compute shared data
        foreach ($plan->getSharedComputations() as $key => $computation) {
            $sharedData[$key] = $this->computeShared($computation, $context);
        }

        // Execute stages
        foreach ($plan->getStages() as $stage) {
            $stageResults = $this->executeStage($stage, $context, $sharedData);

            foreach ($stageResults as $guardName => $result) {
                $results[$guardName] = $result;
                $guardsExecuted++;
            }

            // Check for early termination
            if ($stage->isTerminationPoint()) {
                $criticalFailure = $this->hasCriticalFailure($stageResults);
                if ($criticalFailure) {
                    $guardsSkipped = count($this->guards) - $guardsExecuted;
                    break;
                }
            }
        }

        $executionTime = microtime(true) - $startTime;

        return new FusionResult(
            $results,
            $guardsExecuted,
            $guardsSkipped,
            $executionTime,
            array_keys($sharedData)
        );
    }

    /**
     * Build dependency graph between guards.
     */
    private function buildDependencyGraph(): void
    {
        $this->dependencyGraph = [];

        foreach ($this->guards as $name => $guard) {
            $this->dependencyGraph[$name] = [
                'depends_on' => $this->getDependencies($guard),
                'provides' => $this->getProvidedData($guard),
            ];
        }
    }

    /**
     * Get guard dependencies.
     */
    private function getDependencies(GuardInterface $guard): array
    {
        // This would ideally be metadata on the guard
        $name = $guard->getName();

        return match ($name) {
            'credential_stuffing' => ['rate_limit', 'brute_force'],
            'session_hijack' => ['session_integrity'],
            'api_abuse' => ['rate_limit'],
            default => [],
        };
    }

    /**
     * Get data provided by guard.
     */
    private function getProvidedData(GuardInterface $guard): array
    {
        $name = $guard->getName();

        return match ($name) {
            'rate_limit' => ['request_count', 'time_window'],
            'sql_injection', 'xss' => ['parsed_input', 'pattern_matches'],
            'session_integrity' => ['session_data', 'session_score'],
            default => [],
        };
    }

    /**
     * Identify opportunities for shared computation.
     */
    private function identifySharedComputations(array $guards): array
    {
        $shared = [];
        $guardNames = array_keys($guards);

        foreach ($this->fusionRules as $computation => $applicableGuards) {
            $intersection = array_intersect($guardNames, $applicableGuards);

            if (count($intersection) >= 2) {
                $shared[$computation] = [
                    'guards' => $intersection,
                    'type' => $computation,
                ];
            }
        }

        // Add input parsing if multiple guards need it
        $inputNeeded = array_filter($guardNames, function ($name) {
            return in_array($name, ['sql_injection', 'xss', 'payload_obfuscation', 'prototype_pollution']);
        });

        if (count($inputNeeded) >= 2) {
            $shared['parsed_input'] = [
                'guards' => $inputNeeded,
                'type' => 'input_parsing',
            ];
        }

        return $shared;
    }

    /**
     * Create execution stages.
     */
    private function createStages(array $guards, array $sharedComputations): array
    {
        $stages = [];
        $processed = [];

        // Stage 1: High priority guards (100-90)
        $stage1Guards = array_filter($guards, fn($g) => $g->getPriority() >= 90);
        if (!empty($stage1Guards)) {
            $stages[] = new ExecutionStage(
                'critical',
                array_keys($stage1Guards),
                true, // Early termination point
                ['parsed_input']
            );
            $processed = array_merge($processed, array_keys($stage1Guards));
        }

        // Stage 2: Medium priority guards (89-70)
        $stage2Guards = array_filter(
            $guards,
            fn($g, $k) => !in_array($k, $processed) && $g->getPriority() >= 70,
            ARRAY_FILTER_USE_BOTH
        );
        if (!empty($stage2Guards)) {
            $stages[] = new ExecutionStage(
                'high',
                array_keys($stage2Guards),
                true,
                ['rate_analysis', 'session_analysis']
            );
            $processed = array_merge($processed, array_keys($stage2Guards));
        }

        // Stage 3: Lower priority guards
        $stage3Guards = array_filter(
            $guards,
            fn($g, $k) => !in_array($k, $processed),
            ARRAY_FILTER_USE_BOTH
        );
        if (!empty($stage3Guards)) {
            $stages[] = new ExecutionStage(
                'normal',
                array_keys($stage3Guards),
                false,
                []
            );
        }

        return $stages;
    }

    /**
     * Add early termination points.
     */
    private function addEarlyTerminationPoints(array $stages): array
    {
        // First stage with critical guards should terminate on failure
        if (!empty($stages)) {
            $stages[0] = $stages[0]->withTerminationPoint(true);
        }

        return $stages;
    }

    /**
     * Compute shared data.
     */
    private function computeShared(array $computation, RuntimeContext $context): mixed
    {
        $request = $context->getRequest();

        return match ($computation['type']) {
            'input_parsing' => $this->parseAllInput($request),
            'rate_analysis' => $this->analyzeRate($request),
            'session_analysis' => $this->analyzeSession($context),
            'pattern_matching' => $this->precompilePatterns(),
            default => null,
        };
    }

    /**
     * Parse all input once.
     */
    private function parseAllInput(object $request): array
    {
        return [
            'query' => $request->query() ?? [],
            'body' => $request->all(),
            'headers' => $request->headers?->all() ?? [],
            'combined_string' => http_build_query($request->all()) . $request->getContent(),
            'content_type' => $request->header('Content-Type'),
            'method' => $request->method(),
        ];
    }

    /**
     * Analyze rate metrics.
     */
    private function analyzeRate(object $request): array
    {
        $ip = $request->ip();
        $cacheKey = "rate:{$ip}";

        $data = Cache::get($cacheKey, [
            'count' => 0,
            'first_request' => time(),
            'last_request' => time(),
        ]);

        $data['count']++;
        $data['last_request'] = time();
        $data['window'] = $data['last_request'] - $data['first_request'];
        $data['rate'] = $data['window'] > 0 ? $data['count'] / $data['window'] * 60 : $data['count'];

        Cache::put($cacheKey, $data, 300);

        return $data;
    }

    /**
     * Analyze session metrics.
     */
    private function analyzeSession(RuntimeContext $context): array
    {
        $session = $context->getRequest()->session();

        return [
            'exists' => $session?->isStarted() ?? false,
            'id' => $session?->getId(),
            'created_at' => $session?->get('_created_at'),
            'last_activity' => $session?->get('_last_activity'),
            'user_id' => $session?->get('user_id'),
        ];
    }

    /**
     * Precompile regex patterns.
     */
    private function precompilePatterns(): array
    {
        return [
            'sql' => '/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|OR|AND)\b/i',
            'xss' => '/<script[^>]*>|javascript:|on\w+\s*=/i',
            'path' => '/\.\.[\/\\\\]/i',
            'cmd' => '/[;&|`$]|\b(cat|ls|pwd|wget|curl|nc)\b/i',
        ];
    }

    /**
     * Execute a single stage.
     */
    private function executeStage(
        ExecutionStage $stage,
        RuntimeContext $context,
        array $sharedData
    ): array {
        $results = [];

        // Inject shared data into context
        $enrichedContext = $context->withSharedData($sharedData);

        foreach ($stage->getGuards() as $guardName) {
            if (!isset($this->guards[$guardName])) {
                continue;
            }

            $guard = $this->guards[$guardName];
            $results[$guardName] = $guard->inspect($enrichedContext);
        }

        return $results;
    }

    /**
     * Check for critical failure.
     */
    private function hasCriticalFailure(array $results): bool
    {
        foreach ($results as $result) {
            if (!$result->isPassed() && $result->getSeverity() === 'critical') {
                return true;
            }
        }
        return false;
    }

    /**
     * Get optimization statistics.
     */
    public function getStatistics(): array
    {
        return [
            'registered_guards' => count($this->guards),
            'fusion_rules' => count($this->fusionRules),
            'potential_optimizations' => count($this->identifySharedComputations($this->guards)),
        ];
    }
}

/**
 * Execution plan.
 */
class ExecutionPlan
{
    public function __construct(
        private array $stages,
        private array $sharedComputations
    ) {}

    public function getStages(): array
    {
        return $this->stages;
    }

    public function getSharedComputations(): array
    {
        return $this->sharedComputations;
    }
}

/**
 * Execution stage.
 */
class ExecutionStage
{
    public function __construct(
        private string $name,
        private array $guards,
        private bool $terminationPoint,
        private array $sharedDataKeys
    ) {}

    public function getName(): string
    {
        return $this->name;
    }

    public function getGuards(): array
    {
        return $this->guards;
    }

    public function isTerminationPoint(): bool
    {
        return $this->terminationPoint;
    }

    public function getSharedDataKeys(): array
    {
        return $this->sharedDataKeys;
    }

    public function withTerminationPoint(bool $value): self
    {
        return new self($this->name, $this->guards, $value, $this->sharedDataKeys);
    }
}

/**
 * Fusion execution result.
 */
class FusionResult
{
    public function __construct(
        public readonly array $results,
        public readonly int $guardsExecuted,
        public readonly int $guardsSkipped,
        public readonly float $executionTime,
        public readonly array $sharedComputations
    ) {}

    public function hasFailures(): bool
    {
        foreach ($this->results as $result) {
            if (!$result->isPassed()) {
                return true;
            }
        }
        return false;
    }

    public function getFailedGuards(): array
    {
        return array_filter($this->results, fn($r) => !$r->isPassed());
    }

    public function toArray(): array
    {
        return [
            'guards_executed' => $this->guardsExecuted,
            'guards_skipped' => $this->guardsSkipped,
            'execution_time_ms' => round($this->executionTime * 1000, 2),
            'shared_computations' => $this->sharedComputations,
            'has_failures' => $this->hasFailures(),
            'failed_guards' => array_keys($this->getFailedGuards()),
        ];
    }
}
