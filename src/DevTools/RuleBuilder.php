<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\DevTools;

use Illuminate\Support\Str;

/**
 * Rule Builder.
 *
 * Fluent API for building custom security rules:
 * - Pattern-based rules
 * - Threshold rules
 * - Composite rules
 * - Export to configuration
 */
class RuleBuilder
{
    private array $rules = [];
    private ?string $currentRule = null;
    private array $currentConfig = [];

    /**
     * Start building a new rule.
     */
    public function rule(string $name): self
    {
        $this->saveCurrentRule();

        $this->currentRule = $name;
        $this->currentConfig = [
            'name' => $name,
            'enabled' => true,
            'priority' => 50,
            'severity' => 'medium',
            'conditions' => [],
            'actions' => [],
            'metadata' => [],
        ];

        return $this;
    }

    /**
     * Set rule description.
     */
    public function description(string $description): self
    {
        $this->currentConfig['description'] = $description;
        return $this;
    }

    /**
     * Set rule priority.
     */
    public function priority(int $priority): self
    {
        $this->currentConfig['priority'] = $priority;
        return $this;
    }

    /**
     * Set rule severity.
     */
    public function severity(string $severity): self
    {
        $this->currentConfig['severity'] = $severity;
        return $this;
    }

    /**
     * Enable/disable rule.
     */
    public function enabled(bool $enabled = true): self
    {
        $this->currentConfig['enabled'] = $enabled;
        return $this;
    }

    /**
     * Add pattern condition.
     */
    public function matchesPattern(string $pattern, array $options = []): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'pattern',
            'pattern' => $pattern,
            'case_sensitive' => $options['case_sensitive'] ?? false,
            'target' => $options['target'] ?? 'any',
            'negate' => $options['negate'] ?? false,
        ];
        return $this;
    }

    /**
     * Add multiple patterns (OR).
     */
    public function matchesAnyPattern(array $patterns, array $options = []): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'pattern_any',
            'patterns' => $patterns,
            'case_sensitive' => $options['case_sensitive'] ?? false,
            'target' => $options['target'] ?? 'any',
        ];
        return $this;
    }

    /**
     * Add all patterns (AND).
     */
    public function matchesAllPatterns(array $patterns, array $options = []): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'pattern_all',
            'patterns' => $patterns,
            'case_sensitive' => $options['case_sensitive'] ?? false,
            'target' => $options['target'] ?? 'any',
        ];
        return $this;
    }

    /**
     * Add threshold condition.
     */
    public function threshold(string $metric, string $operator, float $value): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'threshold',
            'metric' => $metric,
            'operator' => $operator,
            'value' => $value,
        ];
        return $this;
    }

    /**
     * Add rate limit condition.
     */
    public function rateLimit(int $requests, int $windowSeconds, ?string $scope = null): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'rate_limit',
            'requests' => $requests,
            'window' => $windowSeconds,
            'scope' => $scope ?? 'ip',
        ];
        return $this;
    }

    /**
     * Add geo condition.
     */
    public function fromCountries(array $countries, bool $allow = false): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'geo',
            'countries' => $countries,
            'mode' => $allow ? 'allow' : 'block',
        ];
        return $this;
    }

    /**
     * Add IP condition.
     */
    public function fromIPs(array $ips, bool $allow = false): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'ip',
            'addresses' => $ips,
            'mode' => $allow ? 'allow' : 'block',
        ];
        return $this;
    }

    /**
     * Add header condition.
     */
    public function hasHeader(string $header, ?string $value = null): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'header',
            'header' => $header,
            'value' => $value,
            'exists' => true,
        ];
        return $this;
    }

    /**
     * Add missing header condition.
     */
    public function missingHeader(string $header): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'header',
            'header' => $header,
            'exists' => false,
        ];
        return $this;
    }

    /**
     * Add path condition.
     */
    public function onPath(string $pattern): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'path',
            'pattern' => $pattern,
        ];
        return $this;
    }

    /**
     * Add method condition.
     */
    public function forMethods(array $methods): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'method',
            'methods' => array_map('strtoupper', $methods),
        ];
        return $this;
    }

    /**
     * Add content type condition.
     */
    public function contentType(string $type): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'content_type',
            'value' => $type,
        ];
        return $this;
    }

    /**
     * Add payload size condition.
     */
    public function payloadSize(string $operator, int $bytes): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'payload_size',
            'operator' => $operator,
            'value' => $bytes,
        ];
        return $this;
    }

    /**
     * Add time-based condition.
     */
    public function duringHours(int $startHour, int $endHour): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'time',
            'start_hour' => $startHour,
            'end_hour' => $endHour,
        ];
        return $this;
    }

    /**
     * Add user agent condition.
     */
    public function userAgentMatches(string $pattern): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'user_agent',
            'pattern' => $pattern,
        ];
        return $this;
    }

    /**
     * Add bot detection condition.
     */
    public function isBot(bool $block = true): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'bot',
            'block' => $block,
        ];
        return $this;
    }

    /**
     * Add entropy condition.
     */
    public function entropyAbove(float $threshold): self
    {
        $this->currentConfig['conditions'][] = [
            'type' => 'entropy',
            'threshold' => $threshold,
        ];
        return $this;
    }

    /**
     * Set block action.
     */
    public function thenBlock(?string $message = null, int $statusCode = 403): self
    {
        $this->currentConfig['actions'][] = [
            'type' => 'block',
            'message' => $message ?? 'Request blocked by security rule',
            'status_code' => $statusCode,
        ];
        return $this;
    }

    /**
     * Set log action.
     */
    public function thenLog(string $level = 'warning'): self
    {
        $this->currentConfig['actions'][] = [
            'type' => 'log',
            'level' => $level,
        ];
        return $this;
    }

    /**
     * Set alert action.
     */
    public function thenAlert(array $channels = ['webhook']): self
    {
        $this->currentConfig['actions'][] = [
            'type' => 'alert',
            'channels' => $channels,
        ];
        return $this;
    }

    /**
     * Set rate limit action.
     */
    public function thenRateLimit(int $requests, int $windowSeconds): self
    {
        $this->currentConfig['actions'][] = [
            'type' => 'rate_limit',
            'requests' => $requests,
            'window' => $windowSeconds,
        ];
        return $this;
    }

    /**
     * Set challenge action.
     */
    public function thenChallenge(string $type = 'captcha'): self
    {
        $this->currentConfig['actions'][] = [
            'type' => 'challenge',
            'challenge_type' => $type,
        ];
        return $this;
    }

    /**
     * Set tag action.
     */
    public function thenTag(array $tags): self
    {
        $this->currentConfig['actions'][] = [
            'type' => 'tag',
            'tags' => $tags,
        ];
        return $this;
    }

    /**
     * Set redirect action.
     */
    public function thenRedirect(string $url, int $statusCode = 302): self
    {
        $this->currentConfig['actions'][] = [
            'type' => 'redirect',
            'url' => $url,
            'status_code' => $statusCode,
        ];
        return $this;
    }

    /**
     * Add metadata.
     */
    public function withMetadata(array $metadata): self
    {
        $this->currentConfig['metadata'] = array_merge(
            $this->currentConfig['metadata'],
            $metadata
        );
        return $this;
    }

    /**
     * Build all rules.
     */
    public function build(): array
    {
        $this->saveCurrentRule();
        return $this->rules;
    }

    /**
     * Export to PHP configuration.
     */
    public function toPhpConfig(): string
    {
        $rules = $this->build();

        $output = "<?php\n\nreturn [\n    'custom_rules' => [\n";

        foreach ($rules as $rule) {
            $output .= $this->ruleToPhpArray($rule, 2);
        }

        $output .= "    ],\n];\n";

        return $output;
    }

    /**
     * Export to JSON.
     */
    public function toJson(): string
    {
        return json_encode(['custom_rules' => $this->build()], JSON_PRETTY_PRINT);
    }

    /**
     * Export to YAML.
     */
    public function toYaml(): string
    {
        return $this->arrayToYaml(['custom_rules' => $this->build()]);
    }

    /**
     * Import from array.
     */
    public function import(array $rules): self
    {
        foreach ($rules as $rule) {
            $this->rules[$rule['name']] = $rule;
        }
        return $this;
    }

    /**
     * Create preset rule for SQL injection.
     */
    public static function sqlInjectionPreset(): self
    {
        return (new self())
            ->rule('sql_injection_protection')
            ->description('Protects against SQL injection attacks')
            ->priority(95)
            ->severity('critical')
            ->matchesAnyPattern([
                '/\bUNION\s+SELECT\b/i',
                '/\bSELECT\s+.*\s+FROM\b/i',
                '/\bINSERT\s+INTO\b/i',
                '/\bDELETE\s+FROM\b/i',
                '/\bDROP\s+(TABLE|DATABASE)\b/i',
                '/\'\s*(OR|AND)\s+[\'"1]/i',
            ], ['target' => 'any'])
            ->thenBlock('SQL injection detected')
            ->thenLog('critical')
            ->thenAlert();
    }

    /**
     * Create preset rule for XSS.
     */
    public static function xssPreset(): self
    {
        return (new self())
            ->rule('xss_protection')
            ->description('Protects against XSS attacks')
            ->priority(94)
            ->severity('high')
            ->matchesAnyPattern([
                '/<script[^>]*>/i',
                '/javascript:/i',
                '/on(load|error|click|mouse)\s*=/i',
                '/<iframe[^>]*>/i',
            ], ['target' => 'any'])
            ->thenBlock('XSS attack detected')
            ->thenLog('warning');
    }

    /**
     * Create preset rule for rate limiting.
     */
    public static function rateLimitPreset(int $requests = 100, int $window = 60): self
    {
        return (new self())
            ->rule('rate_limit')
            ->description('Rate limiting protection')
            ->priority(80)
            ->severity('medium')
            ->rateLimit($requests, $window)
            ->thenRateLimit($requests, $window)
            ->thenLog('info');
    }

    /**
     * Create preset rule for bot detection.
     */
    public static function botDetectionPreset(): self
    {
        return (new self())
            ->rule('bot_detection')
            ->description('Blocks known bot signatures')
            ->priority(70)
            ->severity('low')
            ->isBot(true)
            ->thenChallenge('captcha')
            ->thenLog('info');
    }

    /**
     * Save current rule.
     */
    private function saveCurrentRule(): void
    {
        if ($this->currentRule !== null) {
            $this->rules[$this->currentRule] = $this->currentConfig;
            $this->currentRule = null;
            $this->currentConfig = [];
        }
    }

    /**
     * Convert rule to PHP array string.
     */
    private function ruleToPhpArray(array $rule, int $indent): string
    {
        $spaces = str_repeat('    ', $indent);
        $output = $spaces . "[\n";

        foreach ($rule as $key => $value) {
            $output .= $spaces . "    '{$key}' => " . $this->valueToPhp($value, $indent + 1) . ",\n";
        }

        $output .= $spaces . "],\n";
        return $output;
    }

    /**
     * Convert value to PHP representation.
     */
    private function valueToPhp(mixed $value, int $indent): string
    {
        if (is_array($value)) {
            if (empty($value)) {
                return '[]';
            }

            if (array_keys($value) === range(0, count($value) - 1)) {
                // Sequential array
                $items = array_map(fn($v) => $this->valueToPhp($v, $indent), $value);
                if (count($items) <= 3 && strlen(implode(', ', $items)) < 60) {
                    return '[' . implode(', ', $items) . ']';
                }
                $spaces = str_repeat('    ', $indent);
                return "[\n{$spaces}    " . implode(",\n{$spaces}    ", $items) . "\n{$spaces}]";
            }

            // Associative array
            return $this->ruleToPhpArray($value, $indent);
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if (is_int($value) || is_float($value)) {
            return (string)$value;
        }

        if (is_null($value)) {
            return 'null';
        }

        return "'" . addslashes($value) . "'";
    }

    /**
     * Convert array to YAML.
     */
    private function arrayToYaml(array $data, int $indent = 0): string
    {
        $output = '';
        $spaces = str_repeat('  ', $indent);

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                if (array_keys($value) === range(0, count($value) - 1)) {
                    // List
                    $output .= "{$spaces}{$key}:\n";
                    foreach ($value as $item) {
                        if (is_array($item)) {
                            $output .= "{$spaces}  -\n" . $this->arrayToYaml($item, $indent + 2);
                        } else {
                            $output .= "{$spaces}  - " . $this->yamlValue($item) . "\n";
                        }
                    }
                } else {
                    // Map
                    $output .= "{$spaces}{$key}:\n" . $this->arrayToYaml($value, $indent + 1);
                }
            } else {
                $output .= "{$spaces}{$key}: " . $this->yamlValue($value) . "\n";
            }
        }

        return $output;
    }

    /**
     * Convert value to YAML representation.
     */
    private function yamlValue(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_null($value)) {
            return 'null';
        }
        if (is_int($value) || is_float($value)) {
            return (string)$value;
        }
        if (preg_match('/^[\w\-\.]+$/', $value)) {
            return $value;
        }
        return '"' . addslashes($value) . '"';
    }

    /**
     * Get rule count.
     */
    public function count(): int
    {
        $this->saveCurrentRule();
        return count($this->rules);
    }

    /**
     * Get rule names.
     */
    public function getRuleNames(): array
    {
        $this->saveCurrentRule();
        return array_keys($this->rules);
    }
}
