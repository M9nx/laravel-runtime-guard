<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Resilience;

/**
 * Adaptive load shedding for runtime guard.
 *
 * Dynamically reduces inspection depth based on system load.
 * Prevents security layer from becoming a bottleneck under pressure.
 */
class LoadShedder
{
    /**
     * Guard priority tiers.
     */
    public const TIER_CRITICAL = 1;
    public const TIER_HIGH = 2;
    public const TIER_MEDIUM = 3;
    public const TIER_LOW = 4;

    private float $cpuThreshold;
    private float $memoryThreshold;
    private int $minimumGuards;
    private array $guardTiers;
    private int $sampleIntervalMs;

    private ?float $lastCpuSample = null;
    private ?float $lastMemorySample = null;
    private ?int $lastSampleTime = null;

    /**
     * Current shedding level (0 = none, 1-4 = tier cutoff).
     */
    private int $currentLevel = 0;

    public function __construct(array $config = [])
    {
        $this->cpuThreshold = $config['cpu_threshold'] ?? 0.8;
        $this->memoryThreshold = $config['memory_threshold'] ?? 0.85;
        $this->minimumGuards = $config['minimum_guards'] ?? 2;
        $this->sampleIntervalMs = $config['sample_interval_ms'] ?? 1000;
        $this->guardTiers = $config['guard_tiers'] ?? [
            // Default tier assignments
            'sql_injection' => self::TIER_CRITICAL,
            'xss' => self::TIER_CRITICAL,
            'command_injection' => self::TIER_CRITICAL,
            'ssrf' => self::TIER_HIGH,
            'deserialization' => self::TIER_HIGH,
            'nosql_injection' => self::TIER_HIGH,
            'mass_assignment' => self::TIER_MEDIUM,
            'graphql' => self::TIER_MEDIUM,
            'credential_stuffing' => self::TIER_MEDIUM,
            'session_integrity' => self::TIER_MEDIUM,
            'file_operation' => self::TIER_LOW,
            'anomaly' => self::TIER_LOW,
        ];
    }

    /**
     * Create from configuration.
     */
    public static function fromConfig(array $config): self
    {
        return new self($config);
    }

    /**
     * Set tier for a guard.
     */
    public function setGuardTier(string $guardName, int $tier): self
    {
        $this->guardTiers[$guardName] = max(1, min(4, $tier));
        return $this;
    }

    /**
     * Check if a guard should run based on current load.
     */
    public function shouldRunGuard(string $guardName): bool
    {
        $this->updateLoadSample();

        if ($this->currentLevel === 0) {
            return true;
        }

        $guardTier = $this->guardTiers[$guardName] ?? self::TIER_MEDIUM;

        return $guardTier <= $this->currentLevel;
    }

    /**
     * Filter guards list based on current load.
     *
     * @param array<string> $guards Guard names
     * @return array<string> Filtered guard names
     */
    public function filterGuards(array $guards): array
    {
        $this->updateLoadSample();

        if ($this->currentLevel === 0) {
            return $guards;
        }

        $filtered = array_filter($guards, function ($guard) {
            $tier = $this->guardTiers[$guard] ?? self::TIER_MEDIUM;
            return $tier <= $this->currentLevel;
        });

        // Ensure minimum guards
        if (count($filtered) < $this->minimumGuards) {
            // Sort by tier and take minimum
            usort($guards, fn($a, $b) => 
                ($this->guardTiers[$a] ?? self::TIER_MEDIUM) <=> 
                ($this->guardTiers[$b] ?? self::TIER_MEDIUM)
            );
            return array_slice($guards, 0, $this->minimumGuards);
        }

        return $filtered;
    }

    /**
     * Update load sample and shedding level.
     */
    private function updateLoadSample(): void
    {
        $now = (int)(microtime(true) * 1000);

        // Rate limit sampling
        if ($this->lastSampleTime !== null && 
            ($now - $this->lastSampleTime) < $this->sampleIntervalMs) {
            return;
        }

        $this->lastSampleTime = $now;
        $this->lastCpuSample = $this->getCpuLoad();
        $this->lastMemorySample = $this->getMemoryUsage();

        $this->currentLevel = $this->calculateSheddingLevel();
    }

    /**
     * Calculate shedding level based on current load.
     */
    private function calculateSheddingLevel(): int
    {
        $cpu = $this->lastCpuSample ?? 0;
        $memory = $this->lastMemorySample ?? 0;

        // Determine pressure level
        $cpuPressure = $cpu / $this->cpuThreshold;
        $memoryPressure = $memory / $this->memoryThreshold;
        $maxPressure = max($cpuPressure, $memoryPressure);

        if ($maxPressure < 0.7) {
            return 0; // No shedding
        }

        if ($maxPressure < 0.85) {
            return self::TIER_HIGH; // Run critical + high
        }

        if ($maxPressure < 1.0) {
            return self::TIER_CRITICAL; // Run critical only
        }

        // Extreme pressure - still run critical
        return self::TIER_CRITICAL;
    }

    /**
     * Get current CPU load (0.0 - 1.0).
     */
    private function getCpuLoad(): float
    {
        // Linux
        if (function_exists('sys_getloadavg')) {
            $load = sys_getloadavg();
            if ($load !== false) {
                // Normalize by CPU count
                $cpuCount = $this->getCpuCount();
                return $load[0] / $cpuCount;
            }
        }

        // Windows - try to get CPU from WMI
        if (PHP_OS_FAMILY === 'Windows') {
            return $this->getWindowsCpuLoad();
        }

        return 0.0;
    }

    /**
     * Get current memory usage (0.0 - 1.0).
     */
    private function getMemoryUsage(): float
    {
        $used = memory_get_usage(true);
        $limit = $this->getMemoryLimit();

        if ($limit <= 0) {
            return 0.0;
        }

        return $used / $limit;
    }

    /**
     * Get PHP memory limit in bytes.
     */
    private function getMemoryLimit(): int
    {
        $limit = ini_get('memory_limit');

        if ($limit === '-1') {
            return PHP_INT_MAX;
        }

        $unit = strtolower(substr($limit, -1));
        $value = (int) $limit;

        return match ($unit) {
            'g' => $value * 1024 * 1024 * 1024,
            'm' => $value * 1024 * 1024,
            'k' => $value * 1024,
            default => $value,
        };
    }

    /**
     * Get CPU count.
     */
    private function getCpuCount(): int
    {
        if (PHP_OS_FAMILY === 'Windows') {
            return (int) ($_ENV['NUMBER_OF_PROCESSORS'] ?? 1);
        }

        if (is_readable('/proc/cpuinfo')) {
            $cpuinfo = file_get_contents('/proc/cpuinfo');
            preg_match_all('/^processor/m', $cpuinfo, $matches);
            return count($matches[0]) ?: 1;
        }

        return 1;
    }

    /**
     * Get Windows CPU load.
     */
    private function getWindowsCpuLoad(): float
    {
        // Simplified - in production use WMI or performance counters
        return 0.5;
    }

    /**
     * Force shedding level (for testing).
     */
    public function forceLevel(int $level): self
    {
        $this->currentLevel = max(0, min(4, $level));
        return $this;
    }

    /**
     * Get current shedding level.
     */
    public function getCurrentLevel(): int
    {
        return $this->currentLevel;
    }

    /**
     * Get statistics.
     */
    public function getStats(): array
    {
        return [
            'current_level' => $this->currentLevel,
            'cpu_load' => $this->lastCpuSample,
            'memory_usage' => $this->lastMemorySample,
            'cpu_threshold' => $this->cpuThreshold,
            'memory_threshold' => $this->memoryThreshold,
            'guard_tiers' => $this->guardTiers,
            'level_description' => match ($this->currentLevel) {
                0 => 'normal - all guards active',
                self::TIER_CRITICAL => 'critical - critical guards only',
                self::TIER_HIGH => 'high - critical + high guards',
                self::TIER_MEDIUM => 'medium - critical + high + medium guards',
                self::TIER_LOW => 'low - all guards active',
                default => 'unknown',
            },
        ];
    }
}
