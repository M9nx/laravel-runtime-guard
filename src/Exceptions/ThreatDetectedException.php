<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Exceptions;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;

/**
 * Exception thrown when a security threat is detected and blocking is enabled.
 */
class ThreatDetectedException extends RuntimeGuardException
{
    public function __construct(
        string $message,
        protected GuardResultInterface $result,
    ) {
        parent::__construct($message);
    }

    public static function fromResult(GuardResultInterface $result): self
    {
        return new self(
            "Security threat detected by [{$result->getGuardName()}]: {$result->getMessage()}",
            $result,
        );
    }

    public function getResult(): GuardResultInterface
    {
        return $this->result;
    }
}
