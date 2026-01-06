<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Console\Commands;

use Illuminate\Console\Command;
use M9nx\RuntimeGuard\GuardManager;

/**
 * Display RuntimeGuard statistics and status.
 */
class StatusCommand extends Command
{
    protected $signature = 'runtime-guard:status';

    protected $description = 'Display RuntimeGuard status and statistics';

    public function handle(GuardManager $manager): int
    {
        $this->info('RuntimeGuard Status');
        $this->line(str_repeat('=', 50));
        $this->newLine();

        // Global status
        $enabled = $manager->isEnabled();
        $this->line('Global Status: ' . ($enabled ? '<fg=green>Enabled</>' : '<fg=red>Disabled</>'));
        $this->line('Response Mode: ' . $manager->getResponseMode()->value);
        $this->newLine();

        // Guards summary
        $guards = $manager->all();
        $enabledCount = count(array_filter($guards, fn ($g) => $g->isEnabled()));

        $this->line('Guards:');
        $this->line("  Total: " . count($guards));
        $this->line("  Enabled: {$enabledCount}");
        $this->line("  Disabled: " . (count($guards) - $enabledCount));
        $this->newLine();

        // Pipeline info
        $config = $manager->getConfig();
        $this->line('Pipeline:');
        $this->line('  Strategy: ' . ($config['pipeline']['strategy'] ?? 'short_circuit'));
        $this->line('  Short-circuit at: ' . ($config['pipeline']['short_circuit_at'] ?? 'high'));
        $this->newLine();

        // Performance settings
        $this->line('Performance:');
        $this->line('  Sampling: ' . ($config['performance']['sampling']['enabled'] ?? false ? 'Enabled' : 'Disabled'));
        if ($config['performance']['sampling']['enabled'] ?? false) {
            $this->line('  Sampling Rate: ' . (($config['performance']['sampling']['rate'] ?? 1.0) * 100) . '%');
        }
        $this->line('  Deduplication: ' . ($config['performance']['deduplication']['enabled'] ?? false ? 'Enabled' : 'Disabled'));
        $this->newLine();

        // Correlation
        $this->line('Correlation:');
        $this->line('  Enabled: ' . ($config['correlation']['enabled'] ?? false ? 'Yes' : 'No'));
        $this->newLine();

        // Progressive enforcement
        $this->line('Progressive Enforcement:');
        $this->line('  Enabled: ' . ($config['progressive']['enabled'] ?? false ? 'Yes' : 'No'));

        return self::SUCCESS;
    }
}
