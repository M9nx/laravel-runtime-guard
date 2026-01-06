<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Console\Commands;

use Illuminate\Console\Command;
use M9nx\RuntimeGuard\GuardManager;

/**
 * List all registered guards and their status.
 */
class ListGuardsCommand extends Command
{
    protected $signature = 'runtime-guard:list 
                            {--enabled : Show only enabled guards}
                            {--disabled : Show only disabled guards}';

    protected $description = 'List all registered RuntimeGuard guards';

    public function handle(GuardManager $manager): int
    {
        $guards = $manager->all();

        if (empty($guards)) {
            $this->warn('No guards registered.');

            return self::SUCCESS;
        }

        $rows = [];

        foreach ($guards as $guard) {
            $enabled = $guard->isEnabled();

            // Apply filters
            if ($this->option('enabled') && ! $enabled) {
                continue;
            }

            if ($this->option('disabled') && $enabled) {
                continue;
            }

            $rows[] = [
                $guard->getName(),
                get_class($guard),
                $enabled ? '<fg=green>✓</>' : '<fg=red>✗</>',
                $guard->getPriority(),
            ];
        }

        if (empty($rows)) {
            $this->info('No guards match the filter criteria.');

            return self::SUCCESS;
        }

        // Sort by priority descending
        usort($rows, fn ($a, $b) => $b[3] <=> $a[3]);

        $this->table(
            ['Name', 'Class', 'Enabled', 'Priority'],
            $rows
        );

        $this->newLine();
        $this->info(sprintf(
            'Total: %d guard(s), %d enabled, %d disabled',
            count($guards),
            count(array_filter($guards, fn ($g) => $g->isEnabled())),
            count(array_filter($guards, fn ($g) => ! $g->isEnabled()))
        ));

        return self::SUCCESS;
    }
}
