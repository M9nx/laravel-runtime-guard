<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Cache;
use M9nx\RuntimeGuard\Performance\LazyGuardResolver;
use M9nx\RuntimeGuard\Performance\SharedMemoryStore;

/**
 * Health Check Controller.
 *
 * Provides endpoint for monitoring RuntimeGuard status.
 */
class HealthCheckController extends Controller
{
    public function __invoke(): JsonResponse
    {
        $health = [
            'status' => 'healthy',
            'timestamp' => now()->toIso8601String(),
            'version' => $this->getPackageVersion(),
            'checks' => [],
        ];

        // Run health checks
        $checks = [
            'guards' => $this->checkGuards(),
            'cache' => $this->checkCache(),
            'config' => $this->checkConfig(),
            'memory' => $this->checkMemory(),
        ];

        $health['checks'] = $checks;

        // Determine overall status
        $hasFailure = collect($checks)->contains(fn($check) => $check['status'] === 'fail');
        $hasWarning = collect($checks)->contains(fn($check) => $check['status'] === 'warn');

        if ($hasFailure) {
            $health['status'] = 'unhealthy';
        } elseif ($hasWarning) {
            $health['status'] = 'degraded';
        }

        $statusCode = match ($health['status']) {
            'healthy' => 200,
            'degraded' => 200,
            'unhealthy' => 503,
        };

        return response()->json($health, $statusCode);
    }

    /**
     * Check guards health.
     */
    protected function checkGuards(): array
    {
        $result = [
            'status' => 'pass',
            'details' => [],
        ];

        try {
            $guards = config('runtime-guard.guards', []);
            $enabledCount = 0;
            $totalCount = count($guards);

            foreach ($guards as $name => $config) {
                if ($config['enabled'] ?? true) {
                    $enabledCount++;
                }
            }

            $result['details'] = [
                'total' => $totalCount,
                'enabled' => $enabledCount,
                'disabled' => $totalCount - $enabledCount,
            ];

            if ($enabledCount === 0) {
                $result['status'] = 'warn';
                $result['message'] = 'No guards are enabled';
            }
        } catch (\Throwable $e) {
            $result['status'] = 'fail';
            $result['message'] = 'Failed to check guards: ' . $e->getMessage();
        }

        return $result;
    }

    /**
     * Check cache health.
     */
    protected function checkCache(): array
    {
        $result = [
            'status' => 'pass',
            'details' => [],
        ];

        try {
            $testKey = 'rtg_health_check_' . uniqid();
            $testValue = 'test_' . time();

            // Test write
            Cache::put($testKey, $testValue, 60);

            // Test read
            $retrieved = Cache::get($testKey);

            // Test delete
            Cache::forget($testKey);

            if ($retrieved !== $testValue) {
                $result['status'] = 'fail';
                $result['message'] = 'Cache read/write mismatch';
            }

            $result['details'] = [
                'driver' => config('cache.default'),
                'working' => $retrieved === $testValue,
            ];
        } catch (\Throwable $e) {
            $result['status'] = 'fail';
            $result['message'] = 'Cache check failed: ' . $e->getMessage();
        }

        return $result;
    }

    /**
     * Check configuration health.
     */
    protected function checkConfig(): array
    {
        $result = [
            'status' => 'pass',
            'details' => [],
        ];

        $requiredConfigs = [
            'runtime-guard.enabled',
            'runtime-guard.mode',
            'runtime-guard.guards',
        ];

        $missing = [];
        foreach ($requiredConfigs as $config) {
            if (config($config) === null) {
                $missing[] = $config;
            }
        }

        if (!empty($missing)) {
            $result['status'] = 'fail';
            $result['message'] = 'Missing required configuration';
            $result['details']['missing'] = $missing;
        } else {
            $result['details'] = [
                'enabled' => config('runtime-guard.enabled'),
                'mode' => config('runtime-guard.mode'),
                'guards_configured' => count(config('runtime-guard.guards', [])),
            ];
        }

        return $result;
    }

    /**
     * Check memory usage.
     */
    protected function checkMemory(): array
    {
        $result = [
            'status' => 'pass',
            'details' => [],
        ];

        $memoryUsage = memory_get_usage(true);
        $memoryPeak = memory_get_peak_usage(true);
        $memoryLimit = $this->parseMemoryLimit(ini_get('memory_limit'));

        $usagePercent = $memoryLimit > 0 ? ($memoryUsage / $memoryLimit) * 100 : 0;

        $result['details'] = [
            'current_mb' => round($memoryUsage / 1024 / 1024, 2),
            'peak_mb' => round($memoryPeak / 1024 / 1024, 2),
            'limit_mb' => round($memoryLimit / 1024 / 1024, 2),
            'usage_percent' => round($usagePercent, 2),
        ];

        if ($usagePercent > 90) {
            $result['status'] = 'fail';
            $result['message'] = 'Memory usage critical';
        } elseif ($usagePercent > 75) {
            $result['status'] = 'warn';
            $result['message'] = 'Memory usage high';
        }

        return $result;
    }

    /**
     * Parse memory limit string to bytes.
     */
    protected function parseMemoryLimit(string $limit): int
    {
        if ($limit === '-1') {
            return PHP_INT_MAX;
        }

        $limit = strtolower(trim($limit));
        $value = (int) $limit;

        $unit = substr($limit, -1);

        return match ($unit) {
            'g' => $value * 1024 * 1024 * 1024,
            'm' => $value * 1024 * 1024,
            'k' => $value * 1024,
            default => $value,
        };
    }

    /**
     * Get package version.
     */
    protected function getPackageVersion(): string
    {
        $composerPath = dirname(__DIR__, 3) . '/composer.json';

        if (file_exists($composerPath)) {
            $composer = json_decode(file_get_contents($composerPath), true);
            return $composer['version'] ?? 'unknown';
        }

        return 'unknown';
    }
}
