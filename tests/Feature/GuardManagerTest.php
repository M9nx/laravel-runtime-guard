<?php

declare(strict_types=1);

use M9nx\RuntimeGuard\Contracts\GuardManagerInterface;
use M9nx\RuntimeGuard\Facades\RuntimeGuard;
use M9nx\RuntimeGuard\Guards\SqlInjectionGuard;
use M9nx\RuntimeGuard\Tests\TestCase;

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
