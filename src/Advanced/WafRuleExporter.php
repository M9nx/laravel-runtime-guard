<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Advanced;

/**
 * WAF Rule Exporter.
 *
 * Exports security rules to various WAF formats:
 * - AWS WAF
 * - Cloudflare
 * - ModSecurity
 * - Nginx
 * - Azure WAF
 */
class WafRuleExporter
{
    private array $config;
    private array $rules = [];

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'include_metadata' => true,
            'priority_start' => 100,
        ], $config);
    }

    /**
     * Add rules to export.
     */
    public function addRules(array $rules): self
    {
        $this->rules = array_merge($this->rules, $rules);
        return $this;
    }

    /**
     * Export to AWS WAF format.
     */
    public function toAwsWaf(): array
    {
        $rules = [];
        $priority = $this->config['priority_start'];

        foreach ($this->rules as $rule) {
            $rules[] = [
                'Name' => $this->sanitizeName($rule['name']),
                'Priority' => $priority++,
                'Statement' => $this->buildAwsStatement($rule),
                'Action' => $this->getAwsAction($rule),
                'VisibilityConfig' => [
                    'SampledRequestsEnabled' => true,
                    'CloudWatchMetricsEnabled' => true,
                    'MetricName' => $this->sanitizeName($rule['name']),
                ],
            ];
        }

        return [
            'Name' => 'RuntimeGuard-Rules',
            'Scope' => 'REGIONAL',
            'DefaultAction' => ['Allow' => new \stdClass()],
            'Rules' => $rules,
        ];
    }

    /**
     * Export to Cloudflare format.
     */
    public function toCloudflare(): array
    {
        $rules = [];

        foreach ($this->rules as $rule) {
            $rules[] = [
                'description' => $rule['description'] ?? $rule['name'],
                'expression' => $this->buildCloudflareExpression($rule),
                'action' => $this->getCloudflareAction($rule),
                'enabled' => $rule['enabled'] ?? true,
            ];
        }

        return $rules;
    }

    /**
     * Export to ModSecurity format.
     */
    public function toModSecurity(): string
    {
        $output = "# RuntimeGuard ModSecurity Rules\n";
        $output .= "# Generated: " . date('Y-m-d H:i:s') . "\n\n";

        $id = 100000;

        foreach ($this->rules as $rule) {
            $output .= $this->buildModSecurityRule($rule, $id++);
            $output .= "\n";
        }

        return $output;
    }

    /**
     * Export to Nginx format.
     */
    public function toNginx(): string
    {
        $output = "# RuntimeGuard Nginx Rules\n";
        $output .= "# Generated: " . date('Y-m-d H:i:s') . "\n\n";

        foreach ($this->rules as $rule) {
            $output .= $this->buildNginxRule($rule);
            $output .= "\n";
        }

        return $output;
    }

    /**
     * Export to Azure WAF format.
     */
    public function toAzureWaf(): array
    {
        $customRules = [];
        $priority = $this->config['priority_start'];

        foreach ($this->rules as $rule) {
            $customRules[] = [
                'name' => $this->sanitizeName($rule['name']),
                'priority' => $priority++,
                'ruleType' => 'MatchRule',
                'matchConditions' => $this->buildAzureConditions($rule),
                'action' => $this->getAzureAction($rule),
            ];
        }

        return [
            'customRules' => $customRules,
        ];
    }

    /**
     * Export to JSON format (generic).
     */
    public function toJson(): string
    {
        return json_encode([
            'metadata' => [
                'generator' => 'RuntimeGuard',
                'version' => '4.0',
                'generated_at' => date('c'),
                'rule_count' => count($this->rules),
            ],
            'rules' => $this->rules,
        ], JSON_PRETTY_PRINT);
    }

    /**
     * Export to YAML format (generic).
     */
    public function toYaml(): string
    {
        $output = "# RuntimeGuard WAF Rules\n";
        $output .= "# Generated: " . date('Y-m-d H:i:s') . "\n\n";
        $output .= "rules:\n";

        foreach ($this->rules as $rule) {
            $output .= "  - name: " . $rule['name'] . "\n";
            $output .= "    enabled: " . ($rule['enabled'] ?? true ? 'true' : 'false') . "\n";
            $output .= "    severity: " . ($rule['severity'] ?? 'medium') . "\n";

            if (!empty($rule['conditions'])) {
                $output .= "    conditions:\n";
                foreach ($rule['conditions'] as $condition) {
                    $output .= "      - type: " . ($condition['type'] ?? 'pattern') . "\n";
                    if (isset($condition['pattern'])) {
                        $output .= "        pattern: \"" . addslashes($condition['pattern']) . "\"\n";
                    }
                }
            }

            if (!empty($rule['actions'])) {
                $output .= "    actions:\n";
                foreach ($rule['actions'] as $action) {
                    $output .= "      - type: " . ($action['type'] ?? 'block') . "\n";
                }
            }

            $output .= "\n";
        }

        return $output;
    }

    /**
     * Build AWS WAF statement.
     */
    private function buildAwsStatement(array $rule): array
    {
        $conditions = $rule['conditions'] ?? [];

        if (empty($conditions)) {
            return ['ByteMatchStatement' => $this->buildDefaultAwsMatch()];
        }

        $statements = [];
        foreach ($conditions as $condition) {
            $statements[] = $this->buildAwsCondition($condition);
        }

        if (count($statements) === 1) {
            return $statements[0];
        }

        return [
            'AndStatement' => [
                'Statements' => $statements,
            ],
        ];
    }

    /**
     * Build AWS condition.
     */
    private function buildAwsCondition(array $condition): array
    {
        $type = $condition['type'] ?? 'pattern';

        return match ($type) {
            'pattern', 'pattern_any' => [
                'RegexMatchStatement' => [
                    'RegexString' => $condition['pattern'] ?? $condition['patterns'][0] ?? '.*',
                    'FieldToMatch' => $this->getAwsFieldToMatch($condition['target'] ?? 'body'),
                    'TextTransformations' => [
                        ['Priority' => 0, 'Type' => 'NONE'],
                    ],
                ],
            ],
            'ip' => [
                'IPSetReferenceStatement' => [
                    'ARN' => 'arn:aws:wafv2:region:account:ipset/name',
                ],
            ],
            'rate_limit' => [
                'RateBasedStatement' => [
                    'Limit' => $condition['requests'] ?? 100,
                    'AggregateKeyType' => 'IP',
                ],
            ],
            default => $this->buildDefaultAwsMatch(),
        };
    }

    /**
     * Get AWS field to match.
     */
    private function getAwsFieldToMatch(string $target): array
    {
        return match ($target) {
            'body' => ['Body' => new \stdClass()],
            'uri', 'path' => ['UriPath' => new \stdClass()],
            'query' => ['QueryString' => new \stdClass()],
            'header' => ['SingleHeader' => ['Name' => 'user-agent']],
            default => ['Body' => new \stdClass()],
        };
    }

    /**
     * Build default AWS match.
     */
    private function buildDefaultAwsMatch(): array
    {
        return [
            'ByteMatchStatement' => [
                'SearchString' => 'blocked',
                'FieldToMatch' => ['Body' => new \stdClass()],
                'TextTransformations' => [
                    ['Priority' => 0, 'Type' => 'NONE'],
                ],
                'PositionalConstraint' => 'CONTAINS',
            ],
        ];
    }

    /**
     * Get AWS action.
     */
    private function getAwsAction(array $rule): array
    {
        $action = $rule['actions'][0]['type'] ?? 'block';

        return match ($action) {
            'block' => ['Block' => new \stdClass()],
            'allow' => ['Allow' => new \stdClass()],
            'count', 'log' => ['Count' => new \stdClass()],
            default => ['Block' => new \stdClass()],
        };
    }

    /**
     * Build Cloudflare expression.
     */
    private function buildCloudflareExpression(array $rule): string
    {
        $conditions = $rule['conditions'] ?? [];
        $expressions = [];

        foreach ($conditions as $condition) {
            $expr = $this->buildCloudflareCondition($condition);
            if ($expr) {
                $expressions[] = $expr;
            }
        }

        return implode(' and ', $expressions) ?: 'true';
    }

    /**
     * Build Cloudflare condition.
     */
    private function buildCloudflareCondition(array $condition): string
    {
        $type = $condition['type'] ?? 'pattern';

        return match ($type) {
            'pattern' => sprintf(
                'http.request.body contains "%s"',
                addslashes($condition['pattern'] ?? '')
            ),
            'ip' => sprintf(
                'ip.src in {%s}',
                implode(' ', $condition['addresses'] ?? [])
            ),
            'path' => sprintf(
                'http.request.uri.path contains "%s"',
                $condition['pattern'] ?? ''
            ),
            'user_agent' => sprintf(
                'http.user_agent contains "%s"',
                $condition['pattern'] ?? ''
            ),
            'geo' => sprintf(
                'ip.geoip.country in {"%s"}',
                implode('" "', $condition['countries'] ?? [])
            ),
            default => '',
        };
    }

    /**
     * Get Cloudflare action.
     */
    private function getCloudflareAction(array $rule): string
    {
        $action = $rule['actions'][0]['type'] ?? 'block';

        return match ($action) {
            'block' => 'block',
            'challenge' => 'challenge',
            'log' => 'log',
            default => 'block',
        };
    }

    /**
     * Build ModSecurity rule.
     */
    private function buildModSecurityRule(array $rule, int $id): string
    {
        $output = "# Rule: {$rule['name']}\n";

        foreach ($rule['conditions'] ?? [] as $condition) {
            $pattern = $condition['pattern'] ?? '';
            $target = $this->getModSecurityTarget($condition['target'] ?? 'any');
            $action = $this->getModSecurityAction($rule);
            $severity = $this->getModSecuritySeverity($rule['severity'] ?? 'medium');

            $output .= "SecRule {$target} \"@rx {$pattern}\" ";
            $output .= "\"id:{$id},phase:2,{$action},severity:{$severity},";
            $output .= "msg:'{$rule['name']}',tag:'RuntimeGuard'\"\n";
        }

        return $output;
    }

    /**
     * Get ModSecurity target.
     */
    private function getModSecurityTarget(string $target): string
    {
        return match ($target) {
            'body' => 'REQUEST_BODY',
            'uri', 'path' => 'REQUEST_URI',
            'query' => 'ARGS',
            'header' => 'REQUEST_HEADERS',
            'any' => 'REQUEST_URI|REQUEST_BODY|ARGS',
            default => 'REQUEST_BODY',
        };
    }

    /**
     * Get ModSecurity action.
     */
    private function getModSecurityAction(array $rule): string
    {
        $action = $rule['actions'][0]['type'] ?? 'block';

        return match ($action) {
            'block' => 'deny,status:403',
            'log' => 'log,pass',
            default => 'deny,status:403',
        };
    }

    /**
     * Get ModSecurity severity.
     */
    private function getModSecuritySeverity(string $severity): string
    {
        return match ($severity) {
            'critical' => 'CRITICAL',
            'high' => 'ERROR',
            'medium' => 'WARNING',
            'low' => 'NOTICE',
            default => 'WARNING',
        };
    }

    /**
     * Build Nginx rule.
     */
    private function buildNginxRule(array $rule): string
    {
        $output = "# Rule: {$rule['name']}\n";

        foreach ($rule['conditions'] ?? [] as $condition) {
            $pattern = $condition['pattern'] ?? '';
            $target = $this->getNginxTarget($condition['target'] ?? 'any');

            $output .= "if ({$target} ~* \"{$pattern}\") {\n";
            $output .= "    return 403;\n";
            $output .= "}\n";
        }

        return $output;
    }

    /**
     * Get Nginx target.
     */
    private function getNginxTarget(string $target): string
    {
        return match ($target) {
            'body' => '$request_body',
            'uri', 'path' => '$request_uri',
            'query' => '$args',
            'user_agent' => '$http_user_agent',
            default => '$request_uri',
        };
    }

    /**
     * Build Azure WAF conditions.
     */
    private function buildAzureConditions(array $rule): array
    {
        $conditions = [];

        foreach ($rule['conditions'] ?? [] as $condition) {
            $conditions[] = [
                'matchVariables' => [
                    [
                        'variableName' => $this->getAzureVariable($condition['target'] ?? 'body'),
                    ],
                ],
                'operator' => 'Regex',
                'matchValues' => [$condition['pattern'] ?? '.*'],
            ];
        }

        return $conditions ?: [
            [
                'matchVariables' => [['variableName' => 'RequestBody']],
                'operator' => 'Contains',
                'matchValues' => ['blocked'],
            ],
        ];
    }

    /**
     * Get Azure variable.
     */
    private function getAzureVariable(string $target): string
    {
        return match ($target) {
            'body' => 'RequestBody',
            'uri', 'path' => 'RequestUri',
            'query' => 'QueryString',
            'header' => 'RequestHeaders',
            default => 'RequestBody',
        };
    }

    /**
     * Get Azure action.
     */
    private function getAzureAction(array $rule): string
    {
        $action = $rule['actions'][0]['type'] ?? 'block';

        return match ($action) {
            'block' => 'Block',
            'allow' => 'Allow',
            'log' => 'Log',
            default => 'Block',
        };
    }

    /**
     * Sanitize rule name.
     */
    private function sanitizeName(string $name): string
    {
        return preg_replace('/[^a-zA-Z0-9_-]/', '_', $name);
    }
}
