<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardInterface;
use M9nx\RuntimeGuard\Context\RuntimeContext;
use M9nx\RuntimeGuard\Results\GuardResult;

/**
 * Prototype Pollution Guard.
 *
 * Detects prototype pollution attack patterns:
 * - __proto__ property access
 * - constructor.prototype manipulation
 * - Object pollution via JSON parsing
 * - Property injection in nested structures
 */
class PrototypePollutionGuard implements GuardInterface
{
    private bool $enabled;
    private array $dangerousKeys;
    private int $maxNestingDepth;
    private bool $strictMode;

    public function __construct(array $config = [])
    {
        $this->enabled = $config['enabled'] ?? true;
        $this->maxNestingDepth = $config['max_nesting_depth'] ?? 10;
        $this->strictMode = $config['strict_mode'] ?? true;
        $this->dangerousKeys = $config['dangerous_keys'] ?? [
            '__proto__',
            'constructor',
            'prototype',
            '__defineGetter__',
            '__defineSetter__',
            '__lookupGetter__',
            '__lookupSetter__',
            '__parent__',
            '__noSuchMethod__',
        ];
    }

    public function inspect(RuntimeContext $context): GuardResult
    {
        if (!$this->enabled) {
            return GuardResult::pass($this->getName());
        }

        $request = $context->getRequest();
        $threats = [];
        $metadata = [];

        // Check all input sources
        $inputs = [
            'query' => $request->query() ?? [],
            'body' => $request->all(),
            'json' => $this->parseJsonBody($request),
        ];

        foreach ($inputs as $location => $data) {
            $result = $this->scanForPollution($data, $location);
            $threats = array_merge($threats, $result);
        }

        // Check URL path for pollution attempts
        $pathResult = $this->scanPath($request->path());
        if ($pathResult) {
            $threats[] = $pathResult;
        }

        // Check headers
        $headerResult = $this->scanHeaders($request);
        $threats = array_merge($threats, $headerResult);

        $metadata['sources_checked'] = count($inputs);
        $metadata['threats_found'] = count($threats);

        if (!empty($threats)) {
            return GuardResult::fail($this->getName(), $threats)
                ->withMetadata($metadata);
        }

        return GuardResult::pass($this->getName())
            ->withMetadata($metadata);
    }

    /**
     * Parse JSON body safely.
     */
    private function parseJsonBody(object $request): array
    {
        $contentType = $request->header('Content-Type', '');

        if (!str_contains($contentType, 'application/json')) {
            return [];
        }

        $content = $request->getContent();
        if (empty($content)) {
            return [];
        }

        $decoded = json_decode($content, true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Scan data for pollution patterns.
     */
    private function scanForPollution(mixed $data, string $location, int $depth = 0, string $path = ''): array
    {
        $threats = [];

        if ($depth > $this->maxNestingDepth) {
            $threats[] = [
                'type' => 'excessive_nesting',
                'severity' => 'medium',
                'message' => 'Excessive nesting depth detected (potential DoS)',
                'details' => [
                    'location' => $location,
                    'path' => $path,
                    'depth' => $depth,
                    'max_allowed' => $this->maxNestingDepth,
                ],
            ];
            return $threats;
        }

        if (is_array($data)) {
            foreach ($data as $key => $value) {
                $currentPath = $path ? "{$path}.{$key}" : (string)$key;

                // Check key for dangerous patterns
                $keyThreat = $this->checkKey((string)$key, $location, $currentPath);
                if ($keyThreat) {
                    $threats[] = $keyThreat;
                }

                // Check string values for encoded patterns
                if (is_string($value)) {
                    $valueThreat = $this->checkValue($value, $location, $currentPath);
                    if ($valueThreat) {
                        $threats[] = $valueThreat;
                    }
                }

                // Recurse into nested structures
                if (is_array($value)) {
                    $nestedThreats = $this->scanForPollution($value, $location, $depth + 1, $currentPath);
                    $threats = array_merge($threats, $nestedThreats);
                }
            }
        }

        return $threats;
    }

    /**
     * Check a key for dangerous patterns.
     */
    private function checkKey(string $key, string $location, string $path): ?array
    {
        // Direct match
        $lowerKey = strtolower($key);
        foreach ($this->dangerousKeys as $dangerous) {
            if ($lowerKey === strtolower($dangerous)) {
                return [
                    'type' => 'prototype_pollution',
                    'severity' => 'critical',
                    'message' => "Prototype pollution attempt detected: {$key}",
                    'details' => [
                        'location' => $location,
                        'path' => $path,
                        'key' => $key,
                        'matched_pattern' => $dangerous,
                    ],
                ];
            }
        }

        // Check for bracket notation bypass: ["__proto__"]
        if (preg_match('/\[[\'"](.*?)[\'"]\]/', $key, $matches)) {
            foreach ($this->dangerousKeys as $dangerous) {
                if (strtolower($matches[1]) === strtolower($dangerous)) {
                    return [
                        'type' => 'prototype_pollution_bypass',
                        'severity' => 'critical',
                        'message' => "Prototype pollution bypass attempt: {$key}",
                        'details' => [
                            'location' => $location,
                            'path' => $path,
                            'key' => $key,
                            'extracted_key' => $matches[1],
                        ],
                    ];
                }
            }
        }

        // Check for encoded patterns
        $decodedKey = $this->decodeKey($key);
        if ($decodedKey !== $key) {
            foreach ($this->dangerousKeys as $dangerous) {
                if (strtolower($decodedKey) === strtolower($dangerous)) {
                    return [
                        'type' => 'encoded_prototype_pollution',
                        'severity' => 'critical',
                        'message' => "Encoded prototype pollution attempt: {$key}",
                        'details' => [
                            'location' => $location,
                            'path' => $path,
                            'original_key' => $key,
                            'decoded_key' => $decodedKey,
                        ],
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Check a value for dangerous patterns.
     */
    private function checkValue(string $value, string $location, string $path): ?array
    {
        // Check for JSON strings containing prototype pollution
        if (str_starts_with(trim($value), '{') || str_starts_with(trim($value), '[')) {
            $decoded = json_decode($value, true);
            if (is_array($decoded)) {
                $nestedThreats = $this->scanForPollution($decoded, "{$location}:json_string", 0, $path);
                if (!empty($nestedThreats)) {
                    return [
                        'type' => 'nested_json_pollution',
                        'severity' => 'high',
                        'message' => 'Prototype pollution in nested JSON string',
                        'details' => [
                            'location' => $location,
                            'path' => $path,
                            'nested_threats' => $nestedThreats,
                        ],
                    ];
                }
            }
        }

        // Check for dangerous property access patterns
        $dangerousPatterns = [
            '/__proto__/i',
            '/constructor\s*\.\s*prototype/i',
            '/Object\s*\.\s*prototype/i',
            '/\[\s*[\'"]__proto__[\'"]\s*\]/i',
            '/\.prototype\s*\./i',
        ];

        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return [
                    'type' => 'pollution_in_value',
                    'severity' => 'high',
                    'message' => 'Prototype pollution pattern in value',
                    'details' => [
                        'location' => $location,
                        'path' => $path,
                        'value_preview' => substr($value, 0, 100),
                        'pattern' => $pattern,
                    ],
                ];
            }
        }

        return null;
    }

    /**
     * Decode potentially encoded key.
     */
    private function decodeKey(string $key): string
    {
        // URL decode
        $decoded = urldecode($key);

        // Unicode decode
        $decoded = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', function ($matches) {
            return mb_convert_encoding(pack('H*', $matches[1]), 'UTF-8', 'UTF-16BE');
        }, $decoded);

        // HTML entity decode
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        return $decoded;
    }

    /**
     * Scan URL path for pollution.
     */
    private function scanPath(string $path): ?array
    {
        foreach ($this->dangerousKeys as $dangerous) {
            if (stripos($path, $dangerous) !== false) {
                return [
                    'type' => 'path_pollution_attempt',
                    'severity' => 'high',
                    'message' => "Prototype pollution attempt in URL path",
                    'details' => [
                        'path' => $path,
                        'matched_pattern' => $dangerous,
                    ],
                ];
            }
        }

        // Check URL-encoded versions
        $decodedPath = urldecode($path);
        if ($decodedPath !== $path) {
            foreach ($this->dangerousKeys as $dangerous) {
                if (stripos($decodedPath, $dangerous) !== false) {
                    return [
                        'type' => 'encoded_path_pollution',
                        'severity' => 'high',
                        'message' => "Encoded prototype pollution in URL path",
                        'details' => [
                            'original_path' => $path,
                            'decoded_path' => $decodedPath,
                            'matched_pattern' => $dangerous,
                        ],
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Scan headers for pollution.
     */
    private function scanHeaders(object $request): array
    {
        $threats = [];
        $headersToCheck = ['Content-Type', 'X-Custom-Data', 'X-Request-Data'];

        foreach ($headersToCheck as $header) {
            $value = $request->header($header);
            if (!$value) {
                continue;
            }

            // Check header value
            foreach ($this->dangerousKeys as $dangerous) {
                if (stripos($value, $dangerous) !== false) {
                    $threats[] = [
                        'type' => 'header_pollution',
                        'severity' => 'medium',
                        'message' => "Prototype pollution pattern in header: {$header}",
                        'details' => [
                            'header' => $header,
                            'value_preview' => substr($value, 0, 100),
                            'matched_pattern' => $dangerous,
                        ],
                    ];
                }
            }
        }

        return $threats;
    }

    public function getName(): string
    {
        return 'prototype_pollution';
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getPriority(): int
    {
        return 96;
    }

    public function getSeverity(): string
    {
        return 'critical';
    }
}
