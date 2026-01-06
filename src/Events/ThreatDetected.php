<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Support\InspectionContext;

/**
 * Event fired when a threat is detected.
 */
class ThreatDetected
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly GuardResultInterface $result,
        public readonly InspectionContext $context,
        public readonly string $actionTaken,
    ) {}

    /**
     * Get the guard name that detected the threat.
     */
    public function getGuardName(): string
    {
        return $this->result->getGuardName();
    }

    /**
     * Get the threat level.
     */
    public function getThreatLevel(): string
    {
        return $this->result->getThreatLevel()->value;
    }

    /**
     * Get the detection message.
     */
    public function getMessage(): string
    {
        return $this->result->getMessage();
    }

    /**
     * Get request IP if available.
     */
    public function getIp(): ?string
    {
        return $this->context->ip();
    }

    /**
     * Get user ID if available.
     */
    public function getUserId(): ?int
    {
        return $this->context->userId();
    }

    /**
     * Convert to array for logging/serialization.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'guard' => $this->getGuardName(),
            'level' => $this->getThreatLevel(),
            'message' => $this->getMessage(),
            'action' => $this->actionTaken,
            'ip' => $this->getIp(),
            'user_id' => $this->getUserId(),
            'context' => $this->context->toArray(),
            'timestamp' => now()->toIso8601String(),
        ];
    }
}
