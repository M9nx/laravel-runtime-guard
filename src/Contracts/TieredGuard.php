<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Contracts;

use M9nx\RuntimeGuard\Support\InspectionContext;

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
     * Return a GuardResultInterface if an obvious threat is found.
     * Return null if the input appears clean or needs deeper inspection.
     */
    public function quickScan(mixed $input, InspectionContext $context): ?GuardResultInterface;

    /**
     * Perform deep inspection on suspicious input.
     *
     * Only called if quickScan() returns null.
     */
    public function deepInspection(mixed $input, InspectionContext $context): GuardResultInterface;
}
