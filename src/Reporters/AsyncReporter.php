<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Reporters;

use Illuminate\Contracts\Queue\ShouldQueue;
use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ReporterInterface;
use M9nx\RuntimeGuard\Jobs\ReportThreatJob;

/**
 * Async reporter that dispatches reports to a queue.
 */
class AsyncReporter implements ReporterInterface
{
    /**
     * @param  array<ReporterInterface>  $reporters
     */
    public function __construct(
        protected array $reporters = [],
        protected string $queue = 'default',
        protected ?string $connection = null,
    ) {}

    /**
     * Create from configuration.
     */
    public static function fromConfig(array $config, array $reporters): self
    {
        return new self(
            reporters: $reporters,
            queue: $config['queue'] ?? 'default',
            connection: $config['connection'] ?? null,
        );
    }

    public function report(GuardResultInterface $result, array $context = []): void
    {
        $job = new ReportThreatJob($result, $context, $this->reporters);

        if ($this->connection) {
            $job->onConnection($this->connection);
        }

        dispatch($job->onQueue($this->queue));
    }

    public function shouldReport(GuardResultInterface $result): bool
    {
        // Delegate to underlying reporters
        foreach ($this->reporters as $reporter) {
            if ($reporter->shouldReport($result)) {
                return true;
            }
        }

        return false;
    }
}
