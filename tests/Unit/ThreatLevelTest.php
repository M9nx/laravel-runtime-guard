<?php

declare(strict_types=1);

use Mounir\RuntimeGuard\Contracts\ThreatLevel;

test('threat level none does not suggest blocking', function () {
    expect(ThreatLevel::NONE->shouldBlock())->toBeFalse();
});

test('threat level low does not suggest blocking', function () {
    expect(ThreatLevel::LOW->shouldBlock())->toBeFalse();
});

test('threat level medium does not suggest blocking', function () {
    expect(ThreatLevel::MEDIUM->shouldBlock())->toBeFalse();
});

test('threat level high suggests blocking', function () {
    expect(ThreatLevel::HIGH->shouldBlock())->toBeTrue();
});

test('threat level critical suggests blocking', function () {
    expect(ThreatLevel::CRITICAL->shouldBlock())->toBeTrue();
});

test('threat levels have correct weights', function () {
    expect(ThreatLevel::NONE->weight())->toBe(0);
    expect(ThreatLevel::LOW->weight())->toBe(1);
    expect(ThreatLevel::MEDIUM->weight())->toBe(2);
    expect(ThreatLevel::HIGH->weight())->toBe(3);
    expect(ThreatLevel::CRITICAL->weight())->toBe(4);
});

test('only non-none threat levels should be logged', function () {
    expect(ThreatLevel::NONE->shouldLog())->toBeFalse();
    expect(ThreatLevel::LOW->shouldLog())->toBeTrue();
    expect(ThreatLevel::MEDIUM->shouldLog())->toBeTrue();
    expect(ThreatLevel::HIGH->shouldLog())->toBeTrue();
    expect(ThreatLevel::CRITICAL->shouldLog())->toBeTrue();
});
