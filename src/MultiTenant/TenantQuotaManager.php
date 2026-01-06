<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\MultiTenant;

use Illuminate\Support\Facades\Cache;

/**
 * Tenant Quota Manager.
 *
 * Manages resource quotas per tenant:
 * - Request quotas
 * - Resource consumption limits
 * - Quota enforcement
 * - Usage analytics
 */
class TenantQuotaManager
{
    private array $config;
    private ?TenantIsolationManager $isolationManager;

    public function __construct(array $config = [], ?TenantIsolationManager $isolationManager = null)
    {
        $this->config = array_merge([
            'default_quotas' => [
                'requests_per_minute' => 1000,
                'requests_per_hour' => 50000,
                'requests_per_day' => 1000000,
                'max_payload_size' => 10485760, // 10MB
                'max_concurrent_requests' => 100,
                'storage_mb' => 1000,
                'api_calls_per_day' => 100000,
            ],
            'enforcement' => 'hard', // soft, hard
            'grace_period_percent' => 10,
            'alert_thresholds' => [50, 75, 90, 100],
        ], $config);

        $this->isolationManager = $isolationManager;
    }

    /**
     * Check if request is within quota.
     */
    public function checkQuota(string $quotaType, ?string $tenantId = null, int $amount = 1): QuotaCheckResult
    {
        $tenantId = $tenantId ?? $this->getCurrentTenantId() ?? 'default';
        $quota = $this->getTenantQuota($tenantId, $quotaType);
        $usage = $this->getUsage($tenantId, $quotaType);

        $remaining = $quota - $usage;
        $percentUsed = $quota > 0 ? ($usage / $quota) * 100 : 0;

        $allowed = match ($this->config['enforcement']) {
            'soft' => true, // Always allow but track
            'hard' => $remaining >= $amount,
            default => $remaining >= $amount,
        };

        // Check grace period for hard enforcement
        if (!$allowed && $this->config['enforcement'] === 'hard') {
            $graceLimit = $quota * (1 + $this->config['grace_period_percent'] / 100);
            $allowed = $usage + $amount <= $graceLimit;
        }

        return new QuotaCheckResult(
            allowed: $allowed,
            quotaType: $quotaType,
            limit: $quota,
            used: $usage,
            remaining: max(0, $remaining),
            percentUsed: $percentUsed,
            resetAt: $this->getResetTime($quotaType)
        );
    }

    /**
     * Consume quota.
     */
    public function consume(string $quotaType, ?string $tenantId = null, int $amount = 1): bool
    {
        $tenantId = $tenantId ?? $this->getCurrentTenantId() ?? 'default';

        $check = $this->checkQuota($quotaType, $tenantId, $amount);
        if (!$check->allowed) {
            return false;
        }

        $this->incrementUsage($tenantId, $quotaType, $amount);
        $this->checkAlertThresholds($tenantId, $quotaType);

        return true;
    }

    /**
     * Get all quotas for tenant.
     */
    public function getTenantQuotas(?string $tenantId = null): array
    {
        $tenantId = $tenantId ?? $this->getCurrentTenantId() ?? 'default';

        $cacheKey = "quota:config:{$tenantId}";
        $custom = Cache::get($cacheKey, []);

        return array_merge($this->config['default_quotas'], $custom);
    }

    /**
     * Set custom quota for tenant.
     */
    public function setTenantQuota(string $tenantId, string $quotaType, int $limit): void
    {
        $cacheKey = "quota:config:{$tenantId}";
        $quotas = Cache::get($cacheKey, []);
        $quotas[$quotaType] = $limit;
        Cache::put($cacheKey, $quotas, 86400 * 30); // 30 days
    }

    /**
     * Get usage statistics.
     */
    public function getUsageStats(?string $tenantId = null): array
    {
        $tenantId = $tenantId ?? $this->getCurrentTenantId() ?? 'default';
        $quotas = $this->getTenantQuotas($tenantId);

        $stats = [];
        foreach (array_keys($quotas) as $quotaType) {
            $check = $this->checkQuota($quotaType, $tenantId);
            $stats[$quotaType] = [
                'limit' => $check->limit,
                'used' => $check->used,
                'remaining' => $check->remaining,
                'percent_used' => round($check->percentUsed, 2),
                'reset_at' => $check->resetAt,
            ];
        }

        return $stats;
    }

    /**
     * Reset quota usage.
     */
    public function resetUsage(string $tenantId, ?string $quotaType = null): void
    {
        if ($quotaType !== null) {
            $this->clearUsage($tenantId, $quotaType);
        } else {
            foreach (array_keys($this->config['default_quotas']) as $type) {
                $this->clearUsage($tenantId, $type);
            }
        }
    }

    /**
     * Get historical usage.
     */
    public function getHistoricalUsage(string $tenantId, string $quotaType, int $days = 7): array
    {
        $history = [];

        for ($i = $days - 1; $i >= 0; $i--) {
            $date = date('Y-m-d', strtotime("-{$i} days"));
            $key = "quota:history:{$tenantId}:{$quotaType}:{$date}";
            $history[$date] = Cache::get($key, 0);
        }

        return $history;
    }

    /**
     * Get quota alerts.
     */
    public function getAlerts(?string $tenantId = null): array
    {
        $tenantId = $tenantId ?? $this->getCurrentTenantId() ?? 'default';
        $key = "quota:alerts:{$tenantId}";
        return Cache::get($key, []);
    }

    /**
     * Clear alerts.
     */
    public function clearAlerts(?string $tenantId = null): void
    {
        $tenantId = $tenantId ?? $this->getCurrentTenantId() ?? 'default';
        $key = "quota:alerts:{$tenantId}";
        Cache::forget($key);
    }

    /**
     * Get tenant quota for specific type.
     */
    private function getTenantQuota(string $tenantId, string $quotaType): int
    {
        $quotas = $this->getTenantQuotas($tenantId);
        return $quotas[$quotaType] ?? 0;
    }

    /**
     * Get current usage.
     */
    private function getUsage(string $tenantId, string $quotaType): int
    {
        $window = $this->getWindowKey($quotaType);
        $key = "quota:usage:{$tenantId}:{$quotaType}:{$window}";
        return (int) Cache::get($key, 0);
    }

    /**
     * Increment usage.
     */
    private function incrementUsage(string $tenantId, string $quotaType, int $amount): void
    {
        $window = $this->getWindowKey($quotaType);
        $key = "quota:usage:{$tenantId}:{$quotaType}:{$window}";
        $ttl = $this->getWindowTtl($quotaType);

        Cache::increment($key, $amount);

        // Ensure TTL is set
        if (Cache::get("{$key}:ttl_set") === null) {
            Cache::put("{$key}:ttl_set", true, $ttl);
        }

        // Track daily history
        $historyKey = "quota:history:{$tenantId}:{$quotaType}:" . date('Y-m-d');
        Cache::increment($historyKey, $amount);
    }

    /**
     * Clear usage for quota type.
     */
    private function clearUsage(string $tenantId, string $quotaType): void
    {
        $windows = ['minute', 'hour', 'day'];
        foreach ($windows as $window) {
            $windowKey = $this->getWindowKeyForType($window);
            $key = "quota:usage:{$tenantId}:{$quotaType}:{$windowKey}";
            Cache::forget($key);
        }
    }

    /**
     * Get window key based on quota type.
     */
    private function getWindowKey(string $quotaType): string
    {
        if (str_contains($quotaType, 'minute')) {
            return date('Y-m-d-H-i');
        } elseif (str_contains($quotaType, 'hour')) {
            return date('Y-m-d-H');
        }
        return date('Y-m-d');
    }

    /**
     * Get window key for specific type.
     */
    private function getWindowKeyForType(string $type): string
    {
        return match ($type) {
            'minute' => date('Y-m-d-H-i'),
            'hour' => date('Y-m-d-H'),
            'day' => date('Y-m-d'),
            default => date('Y-m-d'),
        };
    }

    /**
     * Get window TTL based on quota type.
     */
    private function getWindowTtl(string $quotaType): int
    {
        if (str_contains($quotaType, 'minute')) {
            return 60;
        } elseif (str_contains($quotaType, 'hour')) {
            return 3600;
        }
        return 86400;
    }

    /**
     * Get reset time for quota.
     */
    private function getResetTime(string $quotaType): int
    {
        if (str_contains($quotaType, 'minute')) {
            return (int) ceil(time() / 60) * 60;
        } elseif (str_contains($quotaType, 'hour')) {
            return (int) ceil(time() / 3600) * 3600;
        }
        return strtotime('tomorrow midnight');
    }

    /**
     * Check and trigger alert thresholds.
     */
    private function checkAlertThresholds(string $tenantId, string $quotaType): void
    {
        $check = $this->checkQuota($quotaType, $tenantId, 0);

        foreach ($this->config['alert_thresholds'] as $threshold) {
            if ($check->percentUsed >= $threshold) {
                $this->addAlert($tenantId, $quotaType, $threshold, $check);
            }
        }
    }

    /**
     * Add quota alert.
     */
    private function addAlert(string $tenantId, string $quotaType, int $threshold, QuotaCheckResult $check): void
    {
        $key = "quota:alerts:{$tenantId}";
        $alerts = Cache::get($key, []);

        $alertKey = "{$quotaType}_{$threshold}";
        if (!isset($alerts[$alertKey])) {
            $alerts[$alertKey] = [
                'quota_type' => $quotaType,
                'threshold' => $threshold,
                'percent_used' => $check->percentUsed,
                'timestamp' => time(),
            ];

            Cache::put($key, $alerts, 86400);
        }
    }

    /**
     * Get current tenant ID.
     */
    private function getCurrentTenantId(): ?string
    {
        return $this->isolationManager?->getCurrentTenant()?->getId();
    }
}

/**
 * Quota Check Result.
 */
class QuotaCheckResult
{
    public function __construct(
        public readonly bool $allowed,
        public readonly string $quotaType,
        public readonly int $limit,
        public readonly int $used,
        public readonly int $remaining,
        public readonly float $percentUsed,
        public readonly int $resetAt
    ) {}

    public function isNearLimit(): bool
    {
        return $this->percentUsed >= 90;
    }

    public function isOverLimit(): bool
    {
        return $this->percentUsed >= 100;
    }

    public function getTimeUntilReset(): int
    {
        return max(0, $this->resetAt - time());
    }
}
