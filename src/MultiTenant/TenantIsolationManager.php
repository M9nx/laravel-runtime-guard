<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\MultiTenant;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Tenant Isolation Manager.
 *
 * Manages tenant context and ensures proper data isolation:
 * - Tenant identification and context management
 * - Data isolation enforcement
 * - Cross-tenant access prevention
 * - Tenant-specific configurations
 */
class TenantIsolationManager
{
    private array $config;
    private ?TenantContext $currentTenant = null;
    private array $tenantCache = [];

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'identifier_header' => 'X-Tenant-ID',
            'identifier_param' => 'tenant_id',
            'identifier_domain' => true,
            'cache_ttl' => 3600,
            'strict_mode' => true,
            'isolation_level' => 'full', // full, partial, none
        ], $config);
    }

    /**
     * Identify tenant from request.
     */
    public function identifyTenant(Request $request): ?TenantContext
    {
        $tenantId = $this->extractTenantId($request);

        if ($tenantId === null) {
            if ($this->config['strict_mode']) {
                throw new TenantIdentificationException('Unable to identify tenant');
            }
            return null;
        }

        $tenant = $this->loadTenant($tenantId);
        $this->currentTenant = $tenant;

        return $tenant;
    }

    /**
     * Get current tenant context.
     */
    public function getCurrentTenant(): ?TenantContext
    {
        return $this->currentTenant;
    }

    /**
     * Set current tenant context.
     */
    public function setCurrentTenant(TenantContext $tenant): void
    {
        $this->currentTenant = $tenant;
    }

    /**
     * Clear tenant context.
     */
    public function clearTenant(): void
    {
        $this->currentTenant = null;
    }

    /**
     * Run callback in tenant context.
     */
    public function runInContext(TenantContext $tenant, callable $callback): mixed
    {
        $previousTenant = $this->currentTenant;
        $this->currentTenant = $tenant;

        try {
            return $callback($tenant);
        } finally {
            $this->currentTenant = $previousTenant;
        }
    }

    /**
     * Check if request is allowed for current tenant.
     */
    public function validateAccess(Request $request, string $resource): AccessValidationResult
    {
        if ($this->currentTenant === null) {
            return new AccessValidationResult(
                allowed: !$this->config['strict_mode'],
                reason: 'No tenant context'
            );
        }

        // Check tenant status
        if (!$this->currentTenant->isActive()) {
            return new AccessValidationResult(
                allowed: false,
                reason: 'Tenant is inactive'
            );
        }

        // Check resource access
        if (!$this->currentTenant->canAccess($resource)) {
            return new AccessValidationResult(
                allowed: false,
                reason: 'Resource access denied for tenant'
            );
        }

        // Check IP restrictions
        if (!$this->validateIpRestrictions($request)) {
            return new AccessValidationResult(
                allowed: false,
                reason: 'IP not allowed for tenant'
            );
        }

        return new AccessValidationResult(allowed: true);
    }

    /**
     * Get tenant-scoped cache key.
     */
    public function scopedCacheKey(string $key): string
    {
        $tenantId = $this->currentTenant?->getId() ?? 'global';
        return "tenant:{$tenantId}:{$key}";
    }

    /**
     * Get tenant-scoped configuration.
     */
    public function getTenantConfig(string $key, mixed $default = null): mixed
    {
        if ($this->currentTenant === null) {
            return $default;
        }

        return $this->currentTenant->getConfig($key, $default);
    }

    /**
     * Check cross-tenant access attempt.
     */
    public function detectCrossTenantAccess(Request $request, string $targetTenantId): bool
    {
        if ($this->currentTenant === null) {
            return false;
        }

        return $this->currentTenant->getId() !== $targetTenantId;
    }

    /**
     * Get isolation statistics.
     */
    public function getIsolationStats(): array
    {
        return [
            'current_tenant' => $this->currentTenant?->getId(),
            'isolation_level' => $this->config['isolation_level'],
            'strict_mode' => $this->config['strict_mode'],
            'cached_tenants' => count($this->tenantCache),
        ];
    }

    /**
     * Extract tenant ID from request.
     */
    private function extractTenantId(Request $request): ?string
    {
        // Try header first
        $tenantId = $request->header($this->config['identifier_header']);
        if ($tenantId !== null) {
            return $tenantId;
        }

        // Try query/body parameter
        $tenantId = $request->input($this->config['identifier_param']);
        if ($tenantId !== null) {
            return (string) $tenantId;
        }

        // Try domain-based identification
        if ($this->config['identifier_domain']) {
            $tenantId = $this->extractFromDomain($request->getHost());
            if ($tenantId !== null) {
                return $tenantId;
            }
        }

        return null;
    }

    /**
     * Extract tenant ID from domain.
     */
    private function extractFromDomain(string $host): ?string
    {
        // Handle subdomain: tenant.example.com
        $parts = explode('.', $host);
        if (count($parts) >= 3) {
            return $parts[0];
        }

        return null;
    }

    /**
     * Load tenant from cache or storage.
     */
    private function loadTenant(string $tenantId): TenantContext
    {
        if (isset($this->tenantCache[$tenantId])) {
            return $this->tenantCache[$tenantId];
        }

        $cacheKey = "tenant:context:{$tenantId}";
        $cached = Cache::get($cacheKey);

        if ($cached !== null) {
            $tenant = TenantContext::fromArray($cached);
            $this->tenantCache[$tenantId] = $tenant;
            return $tenant;
        }

        // Create default tenant context (in real app, load from database)
        $tenant = new TenantContext($tenantId);
        
        Cache::put($cacheKey, $tenant->toArray(), $this->config['cache_ttl']);
        $this->tenantCache[$tenantId] = $tenant;

        return $tenant;
    }

    /**
     * Validate IP restrictions for tenant.
     */
    private function validateIpRestrictions(Request $request): bool
    {
        $allowedIps = $this->currentTenant->getAllowedIps();

        if (empty($allowedIps)) {
            return true; // No restrictions
        }

        $clientIp = $request->ip();

        foreach ($allowedIps as $allowed) {
            if ($this->ipMatches($clientIp, $allowed)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if IP matches pattern.
     */
    private function ipMatches(string $ip, string $pattern): bool
    {
        if (str_contains($pattern, '/')) {
            return $this->ipInCidr($ip, $pattern);
        }

        if (str_contains($pattern, '*')) {
            $regex = '/^' . str_replace(['*', '.'], ['.*', '\\.'], $pattern) . '$/';
            return (bool) preg_match($regex, $ip);
        }

        return $ip === $pattern;
    }

    /**
     * Check if IP is in CIDR range.
     */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr);
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - (int) $bits);

        return ($ip & $mask) === ($subnet & $mask);
    }
}

/**
 * Tenant Context.
 */
class TenantContext
{
    private string $id;
    private string $name;
    private bool $active;
    private array $config;
    private array $allowedIps;
    private array $allowedResources;
    private array $metadata;

    public function __construct(
        string $id,
        string $name = '',
        bool $active = true,
        array $config = [],
        array $allowedIps = [],
        array $allowedResources = ['*'],
        array $metadata = []
    ) {
        $this->id = $id;
        $this->name = $name ?: $id;
        $this->active = $active;
        $this->config = $config;
        $this->allowedIps = $allowedIps;
        $this->allowedResources = $allowedResources;
        $this->metadata = $metadata;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function isActive(): bool
    {
        return $this->active;
    }

    public function getConfig(string $key, mixed $default = null): mixed
    {
        return $this->config[$key] ?? $default;
    }

    public function getAllConfig(): array
    {
        return $this->config;
    }

    public function getAllowedIps(): array
    {
        return $this->allowedIps;
    }

    public function canAccess(string $resource): bool
    {
        if (in_array('*', $this->allowedResources)) {
            return true;
        }

        foreach ($this->allowedResources as $allowed) {
            if ($resource === $allowed || fnmatch($allowed, $resource)) {
                return true;
            }
        }

        return false;
    }

    public function getMetadata(string $key = null): mixed
    {
        if ($key === null) {
            return $this->metadata;
        }
        return $this->metadata[$key] ?? null;
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'active' => $this->active,
            'config' => $this->config,
            'allowed_ips' => $this->allowedIps,
            'allowed_resources' => $this->allowedResources,
            'metadata' => $this->metadata,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            $data['id'],
            $data['name'] ?? '',
            $data['active'] ?? true,
            $data['config'] ?? [],
            $data['allowed_ips'] ?? [],
            $data['allowed_resources'] ?? ['*'],
            $data['metadata'] ?? []
        );
    }
}

/**
 * Access Validation Result.
 */
class AccessValidationResult
{
    public function __construct(
        public readonly bool $allowed,
        public readonly ?string $reason = null
    ) {}
}

/**
 * Tenant Identification Exception.
 */
class TenantIdentificationException extends \Exception {}
