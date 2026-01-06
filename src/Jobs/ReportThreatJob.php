<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ReporterInterface;
use Mounir\RuntimeGuard\Support\GuardResult;

/**
 * Queued job for async threat reporting.
 */
class ReportThreatJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * Serializable representation of the result.
     *
     * @var array<string, mixed>
     */
    protected array $resultData;

    /**
     * Reporter class names to use.
     *
     * @var array<class-string<ReporterInterface>>
     */
    protected array $reporterClasses;

    /**
     * @param  array<string, mixed>  $context
     * @param  array<ReporterInterface>  $reporters
     */
    public function __construct(
        GuardResultInterface $result,
        protected array $context,
        array $reporters,
    ) {
        // Serialize result data for queue transport
        $this->resultData = $this->serializeResult($result);

        // Store reporter class names
        $this->reporterClasses = array_map(
            fn (ReporterInterface $r) => get_class($r),
            $reporters
        );
    }

    public function handle(): void
    {
        $result = $this->deserializeResult();

        foreach ($this->reporterClasses as $reporterClass) {
            $reporter = app($reporterClass);

            if ($reporter->shouldReport($result)) {
                $reporter->report($result, $this->context);
            }
        }
    }

    /**
     * Serialize result for queue transport.
     *
     * @return array<string, mixed>
     */
    protected function serializeResult(GuardResultInterface $result): array
    {
        return [
            'guard_name' => $result->getGuardName(),
            'passed' => $result->passed(),
            'threat_level' => $result->getThreatLevel()->value,
            'message' => $result->getMessage(),
            'metadata' => $result->getMetadata(),
        ];
    }

    /**
     * Deserialize result from queue.
     */
    protected function deserializeResult(): GuardResultInterface
    {
        if ($this->resultData['passed']) {
            return GuardResult::pass(
                $this->resultData['guard_name'],
                $this->resultData['message']
            );
        }

        return GuardResult::fail(
            $this->resultData['guard_name'],
            \Mounir\RuntimeGuard\Contracts\ThreatLevel::from($this->resultData['threat_level']),
            $this->resultData['message'],
            $this->resultData['metadata']
        );
    }
}
