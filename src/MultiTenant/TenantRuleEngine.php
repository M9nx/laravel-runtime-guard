<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\MultiTenant;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Tenant Rule Engine.
 *
 * Manages per-tenant security rules:
 * - Tenant-specific guard configurations
 * - Rule inheritance and overrides
 * - Dynamic rule evaluation
 * - Rule versioning
 */
class TenantRuleEngine
{
    private array $config;
    private array $ruleCache = [];
    private ?TenantIsolationManager $isolationManager;

    public function __construct(array $config = [], ?TenantIsolationManager $isolationManager = null)
    {
        $this->config = array_merge([
            'cache_ttl' => 3600,
            'allow_override' => true,
            'inheritance' => true,
            'default_rules' => [],
        ], $config);

        $this->isolationManager = $isolationManager;
    }

    /**
     * Get rules for current tenant.
     */
    public function getRulesForTenant(?string $tenantId = null): TenantRuleSet
    {
        $tenantId = $tenantId ?? $this->getCurrentTenantId();

        if ($tenantId === null) {
            return new TenantRuleSet('default', $this->config['default_rules']);
        }

        if (isset($this->ruleCache[$tenantId])) {
            return $this->ruleCache[$tenantId];
        }

        $rules = $this->loadRules($tenantId);
        $this->ruleCache[$tenantId] = $rules;

        return $rules;
    }

    /**
     * Set rules for tenant.
     */
    public function setRulesForTenant(string $tenantId, array $rules): void
    {
        $ruleSet = new TenantRuleSet($tenantId, $rules);
        
        $cacheKey = "tenant:rules:{$tenantId}";
        Cache::put($cacheKey, $ruleSet->toArray(), $this->config['cache_ttl']);
        
        $this->ruleCache[$tenantId] = $ruleSet;
    }

    /**
     * Update specific rule for tenant.
     */
    public function updateRule(string $tenantId, string $ruleKey, array $ruleConfig): void
    {
        $rules = $this->getRulesForTenant($tenantId);
        $rules->setRule($ruleKey, $ruleConfig);
        
        $this->setRulesForTenant($tenantId, $rules->toArray()['rules']);
    }

    /**
     * Evaluate rules against request.
     */
    public function evaluate(Request $request, ?string $tenantId = null): RuleEvaluationResult
    {
        $tenantId = $tenantId ?? $this->getCurrentTenantId();
        $rules = $this->getRulesForTenant($tenantId);

        $violations = [];
        $appliedRules = [];
        $startTime = microtime(true);

        foreach ($rules->getActiveRules() as $ruleName => $rule) {
            $result = $this->evaluateRule($request, $ruleName, $rule);
            $appliedRules[$ruleName] = $result;

            if ($result['violated']) {
                $violations[] = [
                    'rule' => $ruleName,
                    'severity' => $rule['severity'] ?? 'medium',
                    'message' => $result['message'],
                ];
            }
        }

        return new RuleEvaluationResult(
            tenantId: $tenantId ?? 'default',
            passed: empty($violations),
            violations: $violations,
            appliedRules: $appliedRules,
            evaluationTime: microtime(true) - $startTime
        );
    }

    /**
     * Get guard configuration for tenant.
     */
    public function getGuardConfig(string $guardName, ?string $tenantId = null): array
    {
        $rules = $this->getRulesForTenant($tenantId);
        return $rules->getGuardConfig($guardName);
    }

    /**
     * Check if guard is enabled for tenant.
     */
    public function isGuardEnabled(string $guardName, ?string $tenantId = null): bool
    {
        $rules = $this->getRulesForTenant($tenantId);
        return $rules->isGuardEnabled($guardName);
    }

    /**
     * Get enabled guards for tenant.
     */
    public function getEnabledGuards(?string $tenantId = null): array
    {
        $rules = $this->getRulesForTenant($tenantId);
        return $rules->getEnabledGuards();
    }

    /**
     * Inherit rules from parent tenant.
     */
    public function inheritRules(string $childTenantId, string $parentTenantId): void
    {
        if (!$this->config['inheritance']) {
            throw new \RuntimeException('Rule inheritance is disabled');
        }

        $parentRules = $this->getRulesForTenant($parentTenantId);
        $childRules = $this->getRulesForTenant($childTenantId);

        $merged = array_merge($parentRules->toArray()['rules'], $childRules->toArray()['rules']);
        $this->setRulesForTenant($childTenantId, $merged);
    }

    /**
     * Load rules from cache/storage.
     */
    private function loadRules(string $tenantId): TenantRuleSet
    {
        $cacheKey = "tenant:rules:{$tenantId}";
        $cached = Cache::get($cacheKey);

        if ($cached !== null) {
            return TenantRuleSet::fromArray($cached);
        }

        // Apply default rules with inheritance
        $rules = $this->config['default_rules'];

        if ($this->config['inheritance']) {
            $rules = $this->applyInheritance($tenantId, $rules);
        }

        return new TenantRuleSet($tenantId, $rules);
    }

    /**
     * Apply rule inheritance.
     */
    private function applyInheritance(string $tenantId, array $rules): array
    {
        // Could extend to support hierarchical tenant structures
        return $rules;
    }

    /**
     * Evaluate single rule.
     */
    private function evaluateRule(Request $request, string $ruleName, array $rule): array
    {
        $violated = false;
        $message = '';

        $type = $rule['type'] ?? 'custom';

        switch ($type) {
            case 'rate_limit':
                $result = $this->evaluateRateLimit($request, $rule);
                $violated = $result['violated'];
                $message = $result['message'];
                break;

            case 'ip_restriction':
                $result = $this->evaluateIpRestriction($request, $rule);
                $violated = $result['violated'];
                $message = $result['message'];
                break;

            case 'path_restriction':
                $result = $this->evaluatePathRestriction($request, $rule);
                $violated = $result['violated'];
                $message = $result['message'];
                break;

            case 'header_requirement':
                $result = $this->evaluateHeaderRequirement($request, $rule);
                $violated = $result['violated'];
                $message = $result['message'];
                break;

            case 'payload_size':
                $result = $this->evaluatePayloadSize($request, $rule);
                $violated = $result['violated'];
                $message = $result['message'];
                break;

            default:
                // Custom rule evaluation via callback
                if (isset($rule['callback']) && is_callable($rule['callback'])) {
                    $result = $rule['callback']($request, $rule);
                    $violated = $result['violated'] ?? false;
                    $message = $result['message'] ?? '';
                }
        }

        return [
            'violated' => $violated,
            'message' => $message,
            'rule_type' => $type,
        ];
    }

    /**
     * Evaluate rate limit rule.
     */
    private function evaluateRateLimit(Request $request, array $rule): array
    {
        $key = 'rate:' . ($rule['scope'] ?? 'ip') . ':' . $request->ip();
        $limit = $rule['limit'] ?? 100;
        $window = $rule['window'] ?? 60;

        $current = Cache::get($key, 0);

        if ($current >= $limit) {
            return ['violated' => true, 'message' => "Rate limit exceeded: {$current}/{$limit}"];
        }

        Cache::put($key, $current + 1, $window);
        return ['violated' => false, 'message' => ''];
    }

    /**
     * Evaluate IP restriction rule.
     */
    private function evaluateIpRestriction(Request $request, array $rule): array
    {
        $clientIp = $request->ip();
        $allowList = $rule['allow'] ?? [];
        $denyList = $rule['deny'] ?? [];

        if (!empty($denyList)) {
            foreach ($denyList as $denied) {
                if ($this->ipMatches($clientIp, $denied)) {
                    return ['violated' => true, 'message' => 'IP is in deny list'];
                }
            }
        }

        if (!empty($allowList)) {
            foreach ($allowList as $allowed) {
                if ($this->ipMatches($clientIp, $allowed)) {
                    return ['violated' => false, 'message' => ''];
                }
            }
            return ['violated' => true, 'message' => 'IP not in allow list'];
        }

        return ['violated' => false, 'message' => ''];
    }

    /**
     * Evaluate path restriction rule.
     */
    private function evaluatePathRestriction(Request $request, array $rule): array
    {
        $path = $request->path();
        $blockedPaths = $rule['blocked'] ?? [];

        foreach ($blockedPaths as $blocked) {
            if (fnmatch($blocked, $path)) {
                return ['violated' => true, 'message' => "Path '{$path}' is restricted"];
            }
        }

        return ['violated' => false, 'message' => ''];
    }

    /**
     * Evaluate header requirement rule.
     */
    private function evaluateHeaderRequirement(Request $request, array $rule): array
    {
        $required = $rule['required'] ?? [];

        foreach ($required as $header => $expectedValue) {
            $value = $request->header($header);

            if ($value === null) {
                return ['violated' => true, 'message' => "Missing required header: {$header}"];
            }

            if ($expectedValue !== '*' && $value !== $expectedValue) {
                return ['violated' => true, 'message' => "Invalid header value for: {$header}"];
            }
        }

        return ['violated' => false, 'message' => ''];
    }

    /**
     * Evaluate payload size rule.
     */
    private function evaluatePayloadSize(Request $request, array $rule): array
    {
        $maxSize = $rule['max_size'] ?? 1048576; // 1MB default
        $contentLength = $request->header('Content-Length', 0);

        if ((int) $contentLength > $maxSize) {
            return ['violated' => true, 'message' => "Payload too large: {$contentLength} > {$maxSize}"];
        }

        return ['violated' => false, 'message' => ''];
    }

    /**
     * Check if IP matches pattern.
     */
    private function ipMatches(string $ip, string $pattern): bool
    {
        if (str_contains($pattern, '/')) {
            [$subnet, $bits] = explode('/', $pattern);
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            $mask = -1 << (32 - (int) $bits);
            return ($ipLong & $mask) === ($subnetLong & $mask);
        }

        return fnmatch($pattern, $ip);
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
 * Tenant Rule Set.
 */
class TenantRuleSet
{
    private string $tenantId;
    private array $rules;
    private array $guardConfigs;
    private int $version;

    public function __construct(string $tenantId, array $rules = [], int $version = 1)
    {
        $this->tenantId = $tenantId;
        $this->rules = $rules['rules'] ?? $rules;
        $this->guardConfigs = $rules['guard_configs'] ?? [];
        $this->version = $version;
    }

    public function getActiveRules(): array
    {
        return array_filter($this->rules, fn($r) => ($r['enabled'] ?? true));
    }

    public function setRule(string $key, array $config): void
    {
        $this->rules[$key] = $config;
        $this->version++;
    }

    public function getGuardConfig(string $guardName): array
    {
        return $this->guardConfigs[$guardName] ?? [];
    }

    public function isGuardEnabled(string $guardName): bool
    {
        return $this->guardConfigs[$guardName]['enabled'] ?? true;
    }

    public function getEnabledGuards(): array
    {
        return array_keys(array_filter(
            $this->guardConfigs,
            fn($config) => $config['enabled'] ?? true
        ));
    }

    public function toArray(): array
    {
        return [
            'tenant_id' => $this->tenantId,
            'rules' => $this->rules,
            'guard_configs' => $this->guardConfigs,
            'version' => $this->version,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            $data['tenant_id'],
            ['rules' => $data['rules'] ?? [], 'guard_configs' => $data['guard_configs'] ?? []],
            $data['version'] ?? 1
        );
    }
}

/**
 * Rule Evaluation Result.
 */
class RuleEvaluationResult
{
    public function __construct(
        public readonly string $tenantId,
        public readonly bool $passed,
        public readonly array $violations,
        public readonly array $appliedRules,
        public readonly float $evaluationTime
    ) {}

    public function hasViolations(): bool
    {
        return !empty($this->violations);
    }

    public function getHighestSeverity(): ?string
    {
        if (empty($this->violations)) {
            return null;
        }

        $severityOrder = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        $highest = 0;
        $result = null;

        foreach ($this->violations as $violation) {
            $severity = $violation['severity'] ?? 'medium';
            if (($severityOrder[$severity] ?? 0) > $highest) {
                $highest = $severityOrder[$severity];
                $result = $severity;
            }
        }

        return $result;
    }
}
