<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Contracts;

use Mounir\RuntimeGuard\Support\InspectionContext;

/**
 * Guards that implement tiered/two-phase inspection.
 *
 * Tiered guards first perform a quick scan to determine if deep
 * inspection is warranted. This optimizes performance by avoiding
 * expensive analysis on obviously clean inputs.
 */
interface TieredGuard extends GuardInterface
{
    /**
     * Perform a quick, cheap scan to detect obvious threats.
     *
     * Return true if the input is suspicious and warrants deep inspection.
     * Return false if the input appears clean.
     */
    public function quickScan(mixed $input, InspectionContext $context): bool;

    /**
     * Perform deep inspection on suspicious input.
     *
     * Only called if quickScan() returns true.
     */
    public function deepInspection(mixed $input, InspectionContext $context): GuardResultInterface;
}
