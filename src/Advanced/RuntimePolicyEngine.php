<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Advanced;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Runtime Policy Engine.
 *
 * Dynamic policy evaluation engine:
 * - Policy definition and evaluation
 * - Context-aware decisions
 * - Policy versioning
 * - Audit logging
 */
class RuntimePolicyEngine
{
    private array $config;
    private array $policies = [];
    private array $evaluationCache = [];

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'cache_decisions' => true,
            'cache_ttl' => 60,
            'audit_enabled' => true,
            'default_action' => 'deny',
        ], $config);
    }

    /**
     * Define a policy.
     */
    public function define(string $name, Policy $policy): self
    {
        $this->policies[$name] = $policy;
        return $this;
    }

    /**
     * Evaluate all applicable policies.
     */
    public function evaluate(Request $request, array $context = []): PolicyDecision
    {
        $context = array_merge($this->buildContext($request), $context);
        $cacheKey = $this->buildCacheKey($context);

        // Check cache
        if ($this->config['cache_decisions'] && isset($this->evaluationCache[$cacheKey])) {
            return $this->evaluationCache[$cacheKey];
        }

        $decisions = [];
        $applicablePolicies = [];

        foreach ($this->policies as $name => $policy) {
            if ($policy->appliesTo($context)) {
                $applicablePolicies[] = $name;
                $decisions[$name] = $policy->evaluate($context);
            }
        }

        $finalDecision = $this->combineDecisions($decisions);

        // Audit
        if ($this->config['audit_enabled']) {
            $this->audit($context, $applicablePolicies, $decisions, $finalDecision);
        }

        // Cache
        if ($this->config['cache_decisions']) {
            $this->evaluationCache[$cacheKey] = $finalDecision;
        }

        return $finalDecision;
    }

    /**
     * Evaluate specific policy.
     */
    public function evaluatePolicy(string $name, array $context): PolicyDecision
    {
        if (!isset($this->policies[$name])) {
            return new PolicyDecision(
                action: 'deny',
                reason: "Policy '{$name}' not found",
                policyName: $name
            );
        }

        return $this->policies[$name]->evaluate($context);
    }

    /**
     * Load policies from configuration.
     */
    public function loadFromConfig(array $policiesConfig): self
    {
        foreach ($policiesConfig as $name => $config) {
            $this->define($name, Policy::fromConfig($config));
        }

        return $this;
    }

    /**
     * Get all defined policies.
     */
    public function getPolicies(): array
    {
        return $this->policies;
    }

    /**
     * Get policy by name.
     */
    public function getPolicy(string $name): ?Policy
    {
        return $this->policies[$name] ?? null;
    }

    /**
     * Remove policy.
     */
    public function removePolicy(string $name): bool
    {
        if (isset($this->policies[$name])) {
            unset($this->policies[$name]);
            return true;
        }
        return false;
    }

    /**
     * Clear evaluation cache.
     */
    public function clearCache(): void
    {
        $this->evaluationCache = [];
    }

    /**
     * Get audit log.
     */
    public function getAuditLog(int $limit = 100): array
    {
        return Cache::get('policy:audit', []);
    }

    /**
     * Build context from request.
     */
    private function buildContext(Request $request): array
    {
        return [
            'ip' => $request->ip(),
            'method' => $request->method(),
            'path' => $request->path(),
            'host' => $request->getHost(),
            'user_agent' => $request->userAgent(),
            'headers' => $request->headers->all(),
            'query' => $request->query(),
            'is_authenticated' => $request->user() !== null,
            'user_id' => $request->user()?->id,
            'user_roles' => $request->user()?->roles ?? [],
            'timestamp' => time(),
            'hour' => (int) date('H'),
            'day_of_week' => (int) date('w'),
        ];
    }

    /**
     * Build cache key from context.
     */
    private function buildCacheKey(array $context): string
    {
        $relevant = [
            'ip' => $context['ip'],
            'path' => $context['path'],
            'method' => $context['method'],
            'user_id' => $context['user_id'] ?? null,
        ];

        return md5(serialize($relevant));
    }

    /**
     * Combine multiple policy decisions.
     */
    private function combineDecisions(array $decisions): PolicyDecision
    {
        if (empty($decisions)) {
            return new PolicyDecision(
                action: $this->config['default_action'],
                reason: 'No applicable policies'
            );
        }

        // Deny takes precedence
        foreach ($decisions as $name => $decision) {
            if ($decision->action === 'deny') {
                return new PolicyDecision(
                    action: 'deny',
                    reason: $decision->reason,
                    policyName: $name,
                    metadata: ['combined_from' => array_keys($decisions)]
                );
            }
        }

        // All allow
        return new PolicyDecision(
            action: 'allow',
            reason: 'All policies passed',
            metadata: ['combined_from' => array_keys($decisions)]
        );
    }

    /**
     * Audit policy evaluation.
     */
    private function audit(array $context, array $policies, array $decisions, PolicyDecision $final): void
    {
        $record = [
            'timestamp' => time(),
            'context' => [
                'ip' => $context['ip'],
                'path' => $context['path'],
                'method' => $context['method'],
                'user_id' => $context['user_id'] ?? null,
            ],
            'policies_evaluated' => $policies,
            'decisions' => array_map(fn($d) => $d->toArray(), $decisions),
            'final_decision' => $final->toArray(),
        ];

        $audit = Cache::get('policy:audit', []);
        array_unshift($audit, $record);
        Cache::put('policy:audit', array_slice($audit, 0, 1000), 86400);
    }
}

/**
 * Policy.
 */
class Policy
{
    private string $name;
    private array $conditions;
    private string $action;
    private string $description;
    private int $priority;
    private array $targets;

    public function __construct(
        string $name,
        array $conditions,
        string $action = 'allow',
        string $description = '',
        int $priority = 50,
        array $targets = []
    ) {
        $this->name = $name;
        $this->conditions = $conditions;
        $this->action = $action;
        $this->description = $description;
        $this->priority = $priority;
        $this->targets = $targets;
    }

    /**
     * Check if policy applies to context.
     */
    public function appliesTo(array $context): bool
    {
        if (empty($this->targets)) {
            return true;
        }

        foreach ($this->targets as $target) {
            if ($this->matchesTarget($target, $context)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Evaluate policy against context.
     */
    public function evaluate(array $context): PolicyDecision
    {
        $allConditionsMet = true;
        $failedConditions = [];

        foreach ($this->conditions as $condition) {
            if (!$this->evaluateCondition($condition, $context)) {
                $allConditionsMet = false;
                $failedConditions[] = $condition;
            }
        }

        if ($allConditionsMet) {
            return new PolicyDecision(
                action: $this->action,
                reason: "Policy '{$this->name}' conditions met",
                policyName: $this->name
            );
        }

        // Invert action if conditions not met
        $invertedAction = $this->action === 'allow' ? 'deny' : 'allow';

        return new PolicyDecision(
            action: $invertedAction,
            reason: "Policy '{$this->name}' conditions not met",
            policyName: $this->name,
            metadata: ['failed_conditions' => $failedConditions]
        );
    }

    /**
     * Evaluate single condition.
     */
    private function evaluateCondition(array $condition, array $context): bool
    {
        $field = $condition['field'] ?? null;
        $operator = $condition['operator'] ?? 'equals';
        $value = $condition['value'] ?? null;

        $contextValue = $this->getContextValue($field, $context);

        return match ($operator) {
            'equals' => $contextValue === $value,
            'not_equals' => $contextValue !== $value,
            'contains' => is_string($contextValue) && str_contains($contextValue, $value),
            'starts_with' => is_string($contextValue) && str_starts_with($contextValue, $value),
            'ends_with' => is_string($contextValue) && str_ends_with($contextValue, $value),
            'matches' => is_string($contextValue) && preg_match($value, $contextValue),
            'in' => is_array($value) && in_array($contextValue, $value),
            'not_in' => is_array($value) && !in_array($contextValue, $value),
            'gt' => is_numeric($contextValue) && $contextValue > $value,
            'gte' => is_numeric($contextValue) && $contextValue >= $value,
            'lt' => is_numeric($contextValue) && $contextValue < $value,
            'lte' => is_numeric($contextValue) && $contextValue <= $value,
            'between' => is_numeric($contextValue) && $contextValue >= $value[0] && $contextValue <= $value[1],
            'exists' => isset($context[$field]),
            'not_exists' => !isset($context[$field]),
            'is_true' => $contextValue === true,
            'is_false' => $contextValue === false,
            'ip_in_range' => $this->ipInRange($contextValue, $value),
            default => false,
        };
    }

    /**
     * Get value from context.
     */
    private function getContextValue(string $field, array $context): mixed
    {
        if (str_contains($field, '.')) {
            $parts = explode('.', $field);
            $value = $context;
            foreach ($parts as $part) {
                $value = $value[$part] ?? null;
                if ($value === null) break;
            }
            return $value;
        }

        return $context[$field] ?? null;
    }

    /**
     * Check if target matches.
     */
    private function matchesTarget(array $target, array $context): bool
    {
        foreach ($target as $field => $pattern) {
            $contextValue = $context[$field] ?? null;

            if ($contextValue === null) {
                return false;
            }

            if (is_string($pattern) && str_contains($pattern, '*')) {
                if (!fnmatch($pattern, $contextValue)) {
                    return false;
                }
            } elseif ($contextValue !== $pattern) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if IP is in range.
     */
    private function ipInRange(?string $ip, $range): bool
    {
        if ($ip === null) return false;

        if (is_array($range)) {
            foreach ($range as $r) {
                if ($this->ipInRange($ip, $r)) {
                    return true;
                }
            }
            return false;
        }

        if (str_contains($range, '/')) {
            [$subnet, $bits] = explode('/', $range);
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            $mask = -1 << (32 - (int) $bits);
            return ($ipLong & $mask) === ($subnetLong & $mask);
        }

        return $ip === $range;
    }

    /**
     * Create policy from config.
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            $config['name'] ?? 'unnamed',
            $config['conditions'] ?? [],
            $config['action'] ?? 'allow',
            $config['description'] ?? '',
            $config['priority'] ?? 50,
            $config['targets'] ?? []
        );
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getPriority(): int
    {
        return $this->priority;
    }
}

/**
 * Policy Decision.
 */
class PolicyDecision
{
    public function __construct(
        public readonly string $action,
        public readonly string $reason,
        public readonly ?string $policyName = null,
        public readonly array $metadata = []
    ) {}

    public function isAllowed(): bool
    {
        return $this->action === 'allow';
    }

    public function isDenied(): bool
    {
        return $this->action === 'deny';
    }

    public function toArray(): array
    {
        return [
            'action' => $this->action,
            'reason' => $this->reason,
            'policy_name' => $this->policyName,
            'metadata' => $this->metadata,
        ];
    }
}
