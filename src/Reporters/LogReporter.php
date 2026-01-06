<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Reporters;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ReporterInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;
use Psr\Log\LoggerInterface;

/**
 * Reports security events to Laravel's logging system.
 */
class LogReporter implements ReporterInterface
{
    protected ThreatLevel $minLevel;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        protected LoggerInterface $logger,
        protected array $config = [],
    ) {
        $this->minLevel = ThreatLevel::tryFrom($config['min_level'] ?? 'low') ?? ThreatLevel::LOW;
    }

    public function report(GuardResultInterface $result, array $context = []): void
    {
        if (! $this->shouldReport($result)) {
            return;
        }

        $level = $this->mapThreatLevelToLogLevel($result->getThreatLevel());

        $this->logger->log($level, 'RuntimeGuard: Security event detected', [
            'guard' => $result->getGuardName(),
            'threat_level' => $result->getThreatLevel()->value,
            'message' => $result->getMessage(),
            'metadata' => $result->getMetadata(),
            'context' => $context,
        ]);
    }

    public function shouldReport(GuardResultInterface $result): bool
    {
        if ($result->passed()) {
            return false;
        }

        return $result->getThreatLevel()->weight() >= $this->minLevel->weight();
    }

    /**
     * Map threat level to PSR-3 log level.
     */
    protected function mapThreatLevelToLogLevel(ThreatLevel $level): string
    {
        return match ($level) {
            ThreatLevel::CRITICAL => 'critical',
            ThreatLevel::HIGH => 'error',
            ThreatLevel::MEDIUM => 'warning',
            ThreatLevel::LOW => 'notice',
            ThreatLevel::NONE => 'debug',
        };
    }
}
