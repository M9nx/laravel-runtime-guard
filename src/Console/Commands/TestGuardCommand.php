<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Console\Commands;

use Illuminate\Console\Command;
use M9nx\RuntimeGuard\GuardManager;
use M9nx\RuntimeGuard\Support\InspectionContext;

/**
 * Test a guard with sample input.
 */
class TestGuardCommand extends Command
{
    protected $signature = 'runtime-guard:test 
                            {guard : The name of the guard to test}
                            {input : The input string to test against}
                            {--json : Output result as JSON}';

    protected $description = 'Test a guard with sample input';

    public function handle(GuardManager $manager): int
    {
        $guardName = $this->argument('guard');
        $input = $this->argument('input');

        if (! $manager->has($guardName)) {
            $this->error("Guard '{$guardName}' not found.");
            $this->newLine();
            $this->info('Available guards:');

            foreach (array_keys($manager->all()) as $name) {
                $this->line("  - {$name}");
            }

            return self::FAILURE;
        }

        $this->info("Testing guard: {$guardName}");
        $this->line("Input: {$input}");
        $this->newLine();

        $context = InspectionContext::forInput($input);
        $result = $manager->inspectWith($guardName, $input, $context->getAllMeta());

        if ($this->option('json')) {
            if ($result instanceof \M9nx\RuntimeGuard\Support\GuardResult) {
                $this->line(json_encode($result->toArray(), JSON_PRETTY_PRINT));
            } else {
                $this->line(json_encode([
                    'guard' => $result->getGuardName(),
                    'passed' => $result->passed(),
                    'threat_level' => $result->getThreatLevel()->value,
                    'message' => $result->getMessage(),
                    'metadata' => $result->getMetadata(),
                ], JSON_PRETTY_PRINT));
            }

            return self::SUCCESS;
        }

        if ($result->passed()) {
            $this->info('✓ PASSED');
            $this->line("Message: {$result->getMessage()}");
        } else {
            $level = $result->getThreatLevel();
            $color = match ($level->value) {
                'critical' => 'red',
                'high' => 'red',
                'medium' => 'yellow',
                'low' => 'cyan',
                default => 'white',
            };

            $this->line("<fg={$color}>✗ FAILED ({$level->value})</>");
            $this->line("Message: {$result->getMessage()}");

            $metadata = $result->getMetadata();
            if (! empty($metadata)) {
                $this->newLine();
                $this->line('Metadata:');
                foreach ($metadata as $key => $value) {
                    $this->line("  {$key}: " . json_encode($value));
                }
            }
        }

        return $result->passed() ? self::SUCCESS : self::FAILURE;
    }
}
