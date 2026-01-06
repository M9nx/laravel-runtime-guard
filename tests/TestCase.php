<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Tests;

use M9nx\RuntimeGuard\RuntimeGuardServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            RuntimeGuardServiceProvider::class,
        ];
    }

    protected function getPackageAliases($app): array
    {
        return [
            'RuntimeGuard' => \M9nx\RuntimeGuard\Facades\RuntimeGuard::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('runtime-guard.enabled', true);
    }
}
