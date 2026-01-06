<?php

declare(strict_types=1);

use Mounir\RuntimeGuard\Contracts\GuardManagerInterface;
use Mounir\RuntimeGuard\Facades\RuntimeGuard;
use Mounir\RuntimeGuard\Guards\SqlInjectionGuard;
use Mounir\RuntimeGuard\Tests\TestCase;

uses(TestCase::class);

test('guard manager is registered in container', function () {
    expect($this->app->make(GuardManagerInterface::class))
        ->toBeInstanceOf(GuardManagerInterface::class);
});

test('facade resolves to guard manager', function () {
    expect(RuntimeGuard::getFacadeRoot())
        ->toBeInstanceOf(GuardManagerInterface::class);
});

test('sql injection guard is registered by default', function () {
    expect(RuntimeGuard::has('sql-injection'))->toBeTrue();
});

test('sql injection guard detects basic patterns', function () {
    $result = RuntimeGuard::inspectWith('sql-injection', "1' OR '1'='1");

    expect($result->failed())->toBeTrue();
    expect($result->getThreatLevel()->value)->toBe('high');
});

test('sql injection guard passes clean input', function () {
    $result = RuntimeGuard::inspectWith('sql-injection', 'Hello, World!');

    expect($result->passed())->toBeTrue();
});
