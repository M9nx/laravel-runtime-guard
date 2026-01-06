<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Testing;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;
use PHPUnit\Framework\Assert;

/**
 * Testing assertions for guard results.
 */
trait GuardAssertions
{
    /**
     * Assert a result passed.
     */
    protected function assertGuardPassed(GuardResultInterface $result, string $message = ''): void
    {
        Assert::assertTrue(
            $result->passed(),
            $message ?: "Expected guard [{$result->getGuardName()}] to pass, but it failed: {$result->getMessage()}"
        );
    }

    /**
     * Assert a result failed.
     */
    protected function assertGuardFailed(GuardResultInterface $result, string $message = ''): void
    {
        Assert::assertTrue(
            $result->failed(),
            $message ?: "Expected guard [{$result->getGuardName()}] to fail, but it passed."
        );
    }

    /**
     * Assert a specific threat level.
     */
    protected function assertThreatLevel(
        GuardResultInterface $result,
        ThreatLevel $expected,
        string $message = ''
    ): void {
        Assert::assertEquals(
            $expected,
            $result->getThreatLevel(),
            $message ?: "Expected threat level [{$expected->value}], got [{$result->getThreatLevel()->value}]"
        );
    }

    /**
     * Assert threat level is at least the given level.
     */
    protected function assertMinimumThreatLevel(
        GuardResultInterface $result,
        ThreatLevel $minimum,
        string $message = ''
    ): void {
        Assert::assertGreaterThanOrEqual(
            $minimum->weight(),
            $result->getThreatLevel()->weight(),
            $message ?: "Expected threat level at least [{$minimum->value}], got [{$result->getThreatLevel()->value}]"
        );
    }

    /**
     * Assert result is from a specific guard.
     */
    protected function assertGuardName(
        GuardResultInterface $result,
        string $expectedName,
        string $message = ''
    ): void {
        Assert::assertEquals(
            $expectedName,
            $result->getGuardName(),
            $message ?: "Expected guard [{$expectedName}], got [{$result->getGuardName()}]"
        );
    }

    /**
     * Assert result message contains string.
     */
    protected function assertMessageContains(
        GuardResultInterface $result,
        string $needle,
        string $message = ''
    ): void {
        Assert::assertStringContainsString(
            $needle,
            $result->getMessage(),
            $message ?: "Expected message to contain [{$needle}]"
        );
    }

    /**
     * Assert result metadata has key.
     */
    protected function assertMetadataHas(
        GuardResultInterface $result,
        string $key,
        string $message = ''
    ): void {
        Assert::assertArrayHasKey(
            $key,
            $result->getMetadata(),
            $message ?: "Expected metadata to have key [{$key}]"
        );
    }

    /**
     * Assert result metadata value.
     */
    protected function assertMetadataEquals(
        GuardResultInterface $result,
        string $key,
        mixed $expected,
        string $message = ''
    ): void {
        $metadata = $result->getMetadata();

        Assert::assertArrayHasKey($key, $metadata, "Metadata key [{$key}] not found");
        Assert::assertEquals(
            $expected,
            $metadata[$key],
            $message ?: "Expected metadata [{$key}] to equal " . json_encode($expected)
        );
    }
}
