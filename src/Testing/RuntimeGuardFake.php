<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Testing;

use Closure;
use Mounir\RuntimeGuard\Contracts\GuardInterface;
use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;
use Mounir\RuntimeGuard\Support\GuardResult;
use PHPUnit\Framework\Assert;

/**
 * Fake guard manager for testing.
 */
class RuntimeGuardFake
{
    /**
     * @var array<array{guard: string, input: mixed, context: array}>
     */
    protected array $inspections = [];

    /**
     * @var array<string, GuardResultInterface>
     */
    protected array $fakeResults = [];

    /**
     * @var array<string, Closure>
     */
    protected array $fakeCallbacks = [];

    protected bool $shouldRecord = true;

    /**
     * Fake a guard to return a specific result.
     */
    public function fake(string $guardName, ?GuardResultInterface $result = null): self
    {
        if ($result === null) {
            $result = GuardResult::pass($guardName);
        }

        $this->fakeResults[$guardName] = $result;

        return $this;
    }

    /**
     * Fake a guard with a callback.
     */
    public function fakeUsing(string $guardName, Closure $callback): self
    {
        $this->fakeCallbacks[$guardName] = $callback;

        return $this;
    }

    /**
     * Make a guard return a threat.
     */
    public function fakeThreat(
        string $guardName,
        ThreatLevel $level = ThreatLevel::HIGH,
        string $message = 'Fake threat detected'
    ): self {
        $this->fakeResults[$guardName] = GuardResult::fail($guardName, $level, $message);

        return $this;
    }

    /**
     * Inspect (records the call and returns fake result).
     */
    public function inspect(mixed $input, array $context = []): array
    {
        $results = [];

        foreach (array_keys($this->fakeResults) as $guardName) {
            $results[] = $this->inspectWith($guardName, $input, $context);
        }

        return $results;
    }

    /**
     * Inspect with a specific guard.
     */
    public function inspectWith(string $guardName, mixed $input, array $context = []): GuardResultInterface
    {
        if ($this->shouldRecord) {
            $this->inspections[] = [
                'guard' => $guardName,
                'input' => $input,
                'context' => $context,
            ];
        }

        // Check for callback
        if (isset($this->fakeCallbacks[$guardName])) {
            return ($this->fakeCallbacks[$guardName])($input, $context);
        }

        // Check for static result
        if (isset($this->fakeResults[$guardName])) {
            return $this->fakeResults[$guardName];
        }

        // Default to pass
        return GuardResult::pass($guardName);
    }

    /**
     * Assert a guard was called.
     */
    public function assertInspected(string $guardName, ?Closure $callback = null): self
    {
        $matching = array_filter(
            $this->inspections,
            fn ($i) => $i['guard'] === $guardName
        );

        Assert::assertNotEmpty(
            $matching,
            "Guard [{$guardName}] was not inspected."
        );

        if ($callback) {
            foreach ($matching as $inspection) {
                if ($callback($inspection['input'], $inspection['context'])) {
                    return $this;
                }
            }

            Assert::fail("Guard [{$guardName}] was inspected but callback did not match.");
        }

        return $this;
    }

    /**
     * Assert a guard was not called.
     */
    public function assertNotInspected(string $guardName): self
    {
        $matching = array_filter(
            $this->inspections,
            fn ($i) => $i['guard'] === $guardName
        );

        Assert::assertEmpty(
            $matching,
            "Guard [{$guardName}] was unexpectedly inspected."
        );

        return $this;
    }

    /**
     * Assert no inspections occurred.
     */
    public function assertNothingInspected(): self
    {
        Assert::assertEmpty(
            $this->inspections,
            'Expected no inspections, but ' . count($this->inspections) . ' occurred.'
        );

        return $this;
    }

    /**
     * Assert a specific input was inspected.
     */
    public function assertInputInspected(mixed $expectedInput): self
    {
        $matching = array_filter(
            $this->inspections,
            fn ($i) => $i['input'] === $expectedInput
        );

        Assert::assertNotEmpty(
            $matching,
            'Expected input was not inspected.'
        );

        return $this;
    }

    /**
     * Assert inspection count.
     */
    public function assertInspectionCount(int $expected): self
    {
        Assert::assertCount(
            $expected,
            $this->inspections,
            "Expected {$expected} inspections, got " . count($this->inspections)
        );

        return $this;
    }

    /**
     * Get all recorded inspections.
     *
     * @return array<array{guard: string, input: mixed, context: array}>
     */
    public function getInspections(): array
    {
        return $this->inspections;
    }

    /**
     * Clear recorded inspections.
     */
    public function clearInspections(): self
    {
        $this->inspections = [];

        return $this;
    }

    /**
     * Temporarily disable recording.
     */
    public function withoutRecording(Closure $callback): mixed
    {
        $this->shouldRecord = false;

        try {
            return $callback();
        } finally {
            $this->shouldRecord = true;
        }
    }
}
