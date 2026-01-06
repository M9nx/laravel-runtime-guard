<?php

declare(strict_types=1);

use Mounir\RuntimeGuard\Contracts\ThreatLevel;
use Mounir\RuntimeGuard\Support\GuardResult;

test('pass creates passing result', function () {
    $result = GuardResult::pass('test-guard', 'All good');

    expect($result->passed())->toBeTrue();
    expect($result->failed())->toBeFalse();
    expect($result->getThreatLevel())->toBe(ThreatLevel::NONE);
    expect($result->getMessage())->toBe('All good');
    expect($result->getGuardName())->toBe('test-guard');
});

test('fail creates failing result', function () {
    $result = GuardResult::fail(
        'test-guard',
        ThreatLevel::HIGH,
        'Threat detected',
        ['key' => 'value']
    );

    expect($result->passed())->toBeFalse();
    expect($result->failed())->toBeTrue();
    expect($result->getThreatLevel())->toBe(ThreatLevel::HIGH);
    expect($result->getMessage())->toBe('Threat detected');
    expect($result->getMetadata())->toBe(['key' => 'value']);
});

test('result can be converted to array', function () {
    $result = GuardResult::fail(
        'test-guard',
        ThreatLevel::MEDIUM,
        'Test message',
        ['foo' => 'bar']
    );

    expect($result->toArray())->toBe([
        'guard' => 'test-guard',
        'passed' => false,
        'threat_level' => 'medium',
        'message' => 'Test message',
        'metadata' => ['foo' => 'bar'],
    ]);
});
