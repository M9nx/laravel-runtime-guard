<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Contracts;

/**
 * Enum representing response modes.
 */
enum ResponseMode: string
{
    /**
     * Block execution and throw exception.
     */
    case BLOCK = 'block';

    /**
     * Log the threat but continue execution.
     */
    case LOG = 'log';

    /**
     * Record internally but take no visible action.
     */
    case SILENT = 'silent';

    /**
     * Process but never block (for testing).
     */
    case DRY_RUN = 'dry_run';
}
