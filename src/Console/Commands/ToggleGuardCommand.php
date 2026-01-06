<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Console\Commands;

use Illuminate\Console\Command;
use Mounir\RuntimeGuard\GuardManager;

/**
 * Toggle guard enable/disable at runtime.
 */
class ToggleGuardCommand extends Command
{
    protected $signature = 'runtime-guard:toggle 
                            {guard : The name of the guard to toggle}
                            {--enable : Enable the guard}
                            {--disable : Disable the guard}';

    protected $description = 'Enable or disable a guard at runtime';

    public function handle(GuardManager $manager): int
    {
        $guardName = $this->argument('guard');

        if (! $manager->has($guardName)) {
            $this->error("Guard '{$guardName}' not found.");

            return self::FAILURE;
        }

        $featureFlags = $manager->getFeatureFlags();

        if ($this->option('enable')) {
            $featureFlags->enable($guardName);
            $this->info("Guard '{$guardName}' has been enabled.");
        } elseif ($this->option('disable')) {
            $featureFlags->disable($guardName);
            $this->warn("Guard '{$guardName}' has been disabled.");
        } else {
            // Toggle current state
            $currentState = $featureFlags->isEnabled($guardName);
            if ($currentState) {
                $featureFlags->disable($guardName);
                $this->warn("Guard '{$guardName}' has been disabled.");
            } else {
                $featureFlags->enable($guardName);
                $this->info("Guard '{$guardName}' has been enabled.");
            }
        }

        return self::SUCCESS;
    }
}
