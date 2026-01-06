<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Reporters;

use Illuminate\Database\ConnectionInterface;
use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ReporterInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Reports security events to a database table.
 */
class DatabaseReporter implements ReporterInterface
{
    protected ThreatLevel $minLevel;

    public function __construct(
        protected ConnectionInterface $database,
        protected string $table = 'security_events',
        protected array $config = [],
    ) {
        $this->minLevel = ThreatLevel::tryFrom($config['min_level'] ?? 'low') ?? ThreatLevel::LOW;
    }

    public function report(GuardResultInterface $result, array $context = []): void
    {
        $this->database->table($this->table)->insert([
            'guard_name' => $result->getGuardName(),
            'threat_level' => $result->getThreatLevel()->value,
            'message' => $result->getMessage(),
            'metadata' => json_encode($result->getMetadata()),
            'context' => json_encode($this->sanitizeContext($context)),
            'ip_address' => $context['ip'] ?? null,
            'user_id' => $context['user_id'] ?? null,
            'route' => $context['route'] ?? null,
            'created_at' => now(),
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
     * Sanitize context for storage.
     */
    protected function sanitizeContext(array $context): array
    {
        // Remove sensitive data
        unset(
            $context['password'],
            $context['token'],
            $context['secret'],
            $context['authorization']
        );

        // Truncate large values
        return array_map(function ($value) {
            if (is_string($value) && strlen($value) > 1000) {
                return substr($value, 0, 1000) . '...[truncated]';
            }

            return $value;
        }, $context);
    }
}
