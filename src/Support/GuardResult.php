<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Support;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Immutable value object representing the result of a guard inspection.
 */
final readonly class GuardResult implements GuardResultInterface
{
    /**
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        private string $guardName,
        private bool $passed,
        private ThreatLevel $threatLevel = ThreatLevel::NONE,
        private string $message = '',
        private array $metadata = [],
    ) {}

    /**
     * Create a passing result (no threat detected).
     */
    public static function pass(string $guardName, string $message = 'No threat detected'): self
    {
        return new self(
            guardName: $guardName,
            passed: true,
            threatLevel: ThreatLevel::NONE,
            message: $message,
        );
    }

    /**
     * Create a failing result (threat detected).
     *
     * @param  array<string, mixed>  $metadata
     */
    public static function fail(
        string $guardName,
        ThreatLevel $threatLevel,
        string $message,
        array $metadata = [],
    ): self {
        return new self(
            guardName: $guardName,
            passed: false,
            threatLevel: $threatLevel,
            message: $message,
            metadata: $metadata,
        );
    }

    public function passed(): bool
    {
        return $this->passed;
    }

    public function failed(): bool
    {
        return ! $this->passed;
    }

    public function getThreatLevel(): ThreatLevel
    {
        return $this->threatLevel;
    }

    public function getMessage(): string
    {
        return $this->message;
    }

    public function getMetadata(): array
    {
        return $this->metadata;
    }

    public function getGuardName(): string
    {
        return $this->guardName;
    }

    /**
     * Convert the result to an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'guard' => $this->guardName,
            'passed' => $this->passed,
            'threat_level' => $this->threatLevel->value,
            'message' => $this->message,
            'metadata' => $this->metadata,
        ];
    }
}
