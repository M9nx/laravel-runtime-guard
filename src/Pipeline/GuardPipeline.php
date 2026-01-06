<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Pipeline;

use Mounir\RuntimeGuard\Contracts\ContextAwareGuard;
use Mounir\RuntimeGuard\Contracts\GuardInterface;
use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\PipelineStrategy;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;
use Mounir\RuntimeGuard\Contracts\TieredGuard;
use Mounir\RuntimeGuard\Support\GuardResult;
use Mounir\RuntimeGuard\Support\InspectionContext;

/**
 * Executes guards according to configured pipeline strategy.
 */
class GuardPipeline
{
    private float $lastExecutionTimeMs = 0;

    private int $guardsExecuted = 0;

    private int $guardsSkipped = 0;

    /**
     * @var callable|null
     */
    private $beforeCallback = null;

    /**
     * @var callable|null
     */
    private $afterCallback = null;

    public function __construct(
        private readonly PipelineStrategy $strategy = PipelineStrategy::SHORT_CIRCUIT,
        private readonly ThreatLevel $shortCircuitAt = ThreatLevel::HIGH,
        private readonly int $thresholdScore = 10,
    ) {}

    /**
     * Create from configuration.
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            strategy: PipelineStrategy::tryFrom($config['strategy'] ?? 'short_circuit') ?? PipelineStrategy::SHORT_CIRCUIT,
            shortCircuitAt: ThreatLevel::tryFrom($config['short_circuit_at'] ?? 'high') ?? ThreatLevel::HIGH,
            thresholdScore: $config['threshold_score'] ?? 10,
        );
    }

    /**
     * Execute guards against input.
     *
     * @param  array<GuardInterface>  $guards
     * @return array<GuardResultInterface>
     */
    public function execute(array $guards, mixed $input, InspectionContext $context): array
    {
        $startTime = hrtime(true);
        $results = [];
        $cumulativeScore = 0;

        $this->guardsExecuted = 0;
        $this->guardsSkipped = 0;

        foreach ($guards as $guard) {
            // Check context applicability
            if ($guard instanceof ContextAwareGuard && ! $guard->appliesTo($context)) {
                $this->guardsSkipped++;

                continue;
            }

            // Execute guard (with tiered support)
            $result = $this->executeGuard($guard, $input, $context);
            $results[] = $result;
            $this->guardsExecuted++;

            // Apply strategy
            if ($this->shouldStopPipeline($result, $cumulativeScore)) {
                break;
            }

            $cumulativeScore += $result->getThreatLevel()->weight();
        }

        $this->lastExecutionTimeMs = (hrtime(true) - $startTime) / 1_000_000;

        return $results;
    }

    /**
     * Execute a single guard.
     */
    private function executeGuard(
        GuardInterface $guard,
        mixed $input,
        InspectionContext $context
    ): GuardResultInterface {
        // Fire before callback
        if ($this->beforeCallback) {
            ($this->beforeCallback)($guard, $input, $context);
        }

        $guardStart = hrtime(true);

        // Handle tiered guards
        if ($guard instanceof TieredGuard) {
            if (! $guard->quickScan($input, $context)) {
                $result = GuardResult::pass($guard->getName(), 'Quick scan passed');
            } else {
                $result = $guard->deepInspection($input, $context);
            }
        } else {
            $result = $guard->inspect($input, $context->getAllMeta());
        }

        $durationMs = (hrtime(true) - $guardStart) / 1_000_000;

        // Fire after callback
        if ($this->afterCallback) {
            ($this->afterCallback)($guard, $result, $durationMs);
        }

        // Augment result with timing if it's our GuardResult class
        if ($result instanceof GuardResult) {
            return $this->augmentResultWithTiming($result, $durationMs);
        }

        return $result;
    }

    /**
     * Determine if pipeline should stop.
     */
    private function shouldStopPipeline(GuardResultInterface $result, int $cumulativeScore): bool
    {
        if ($result->passed()) {
            return false;
        }

        return match ($this->strategy) {
            PipelineStrategy::FULL => false,
            PipelineStrategy::SHORT_CIRCUIT => $result->getThreatLevel()->weight() >= $this->shortCircuitAt->weight(),
            PipelineStrategy::THRESHOLD => $cumulativeScore + $result->getThreatLevel()->weight() >= $this->thresholdScore,
        };
    }

    /**
     * Augment result with timing metadata.
     */
    private function augmentResultWithTiming(GuardResult $result, float $durationMs): GuardResult
    {
        $metadata = $result->getMetadata();
        $metadata['duration_ms'] = round($durationMs, 3);

        return new GuardResult(
            guardName: $result->getGuardName(),
            passed: $result->passed(),
            threatLevel: $result->getThreatLevel(),
            message: $result->getMessage(),
            metadata: $metadata,
        );
    }

    /**
     * Get last execution time in milliseconds.
     */
    public function getLastExecutionTimeMs(): float
    {
        return round($this->lastExecutionTimeMs, 3);
    }

    /**
     * Get count of guards executed in last run.
     */
    public function getGuardsExecuted(): int
    {
        return $this->guardsExecuted;
    }

    /**
     * Get count of guards skipped in last run.
     */
    public function getGuardsSkipped(): int
    {
        return $this->guardsSkipped;
    }

    /**
     * Get execution statistics.
     *
     * @return array{duration_ms: float, executed: int, skipped: int, strategy: string}
     */
    public function getStats(): array
    {
        return [
            'duration_ms' => $this->getLastExecutionTimeMs(),
            'executed' => $this->guardsExecuted,
            'skipped' => $this->guardsSkipped,
            'strategy' => $this->strategy->value,
        ];
    }

    /**
     * Set before inspection callback.
     */
    public function setBeforeCallback(callable $callback): static
    {
        $this->beforeCallback = $callback;

        return $this;
    }

    /**
     * Set after inspection callback.
     */
    public function setAfterCallback(callable $callback): static
    {
        $this->afterCallback = $callback;

        return $this;
    }
}
