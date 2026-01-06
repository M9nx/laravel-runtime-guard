<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Support;

/**
 * Decides whether to inspect a request based on sampling configuration.
 */
final class SamplingDecider
{
    /**
     * @param  array<string>  $alwaysInspectIps
     * @param  array<string>  $alwaysInspectRoutes
     */
    public function __construct(
        private readonly bool $enabled = false,
        private readonly float $rate = 1.0,
        private readonly array $alwaysInspectIps = [],
        private readonly array $alwaysInspectRoutes = [],
    ) {}

    /**
     * Create from configuration array.
     *
     * @param  array<string, mixed>  $config
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            enabled: $config['enabled'] ?? false,
            rate: $config['rate'] ?? 1.0,
            alwaysInspectIps: $config['always_inspect']['ips'] ?? [],
            alwaysInspectRoutes: $config['always_inspect']['routes'] ?? [],
        );
    }

    /**
     * Decide if this request should be inspected.
     */
    public function shouldInspect(InspectionContext $context): bool
    {
        // If sampling is disabled, always inspect
        if (! $this->enabled) {
            return true;
        }

        // Always inspect specific IPs
        if ($this->shouldAlwaysInspectIp($context->ip())) {
            return true;
        }

        // Always inspect specific routes
        if ($this->shouldAlwaysInspectRoute($context)) {
            return true;
        }

        // Apply sampling rate
        return $this->passesSampling();
    }

    /**
     * Check if IP should always be inspected.
     */
    private function shouldAlwaysInspectIp(?string $ip): bool
    {
        if ($ip === null || empty($this->alwaysInspectIps)) {
            return false;
        }

        foreach ($this->alwaysInspectIps as $pattern) {
            if ($this->ipMatches($ip, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if route should always be inspected.
     */
    private function shouldAlwaysInspectRoute(InspectionContext $context): bool
    {
        if (empty($this->alwaysInspectRoutes)) {
            return false;
        }

        foreach ($this->alwaysInspectRoutes as $pattern) {
            if ($context->pathMatches($pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Apply random sampling.
     */
    private function passesSampling(): bool
    {
        if ($this->rate >= 1.0) {
            return true;
        }

        if ($this->rate <= 0.0) {
            return false;
        }

        return (mt_rand() / mt_getrandmax()) < $this->rate;
    }

    /**
     * Check if IP matches pattern (supports CIDR).
     */
    private function ipMatches(string $ip, string $pattern): bool
    {
        // Exact match
        if ($ip === $pattern) {
            return true;
        }

        // Wildcard match
        if (str_contains($pattern, '*')) {
            return fnmatch($pattern, $ip);
        }

        // CIDR match
        if (str_contains($pattern, '/')) {
            return $this->ipInCidr($ip, $pattern);
        }

        return false;
    }

    /**
     * Check if IP is in CIDR range.
     */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $mask] = explode('/', $cidr);

        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $mask = (int) $mask;
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);

        if ($ip === false || $subnet === false) {
            return false;
        }

        $mask = ~((1 << (32 - $mask)) - 1);

        return ($ip & $mask) === ($subnet & $mask);
    }
}
