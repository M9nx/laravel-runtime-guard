<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardInterface;
use M9nx\RuntimeGuard\Context\RuntimeContext;
use M9nx\RuntimeGuard\Results\GuardResult;
use Illuminate\Support\Facades\Cache;

/**
 * API Abuse Guard.
 *
 * Detects API-specific abuse patterns:
 * - Enumeration attacks (user IDs, resources)
 * - GraphQL abuse (deep queries, batching attacks)
 * - API versioning exploits
 * - Parameter pollution
 * - Mass assignment attempts
 * - Excessive field selection
 * - Pagination abuse
 */
class ApiAbuseGuard implements GuardInterface
{
    private bool $enabled;
    private int $enumerationThreshold;
    private int $maxGraphQLDepth;
    private int $maxBatchOperations;
    private int $maxFieldsPerQuery;
    private int $maxPageSize;
    private int $sequentialRequestWindow;
    private array $sensitiveParameters;

    public function __construct(array $config = [])
    {
        $this->enabled = $config['enabled'] ?? true;
        $this->enumerationThreshold = $config['enumeration_threshold'] ?? 10;
        $this->maxGraphQLDepth = $config['max_graphql_depth'] ?? 7;
        $this->maxBatchOperations = $config['max_batch_operations'] ?? 10;
        $this->maxFieldsPerQuery = $config['max_fields_per_query'] ?? 50;
        $this->maxPageSize = $config['max_page_size'] ?? 1000;
        $this->sequentialRequestWindow = $config['sequential_request_window'] ?? 60;
        $this->sensitiveParameters = $config['sensitive_parameters'] ?? [
            'role', 'is_admin', 'permissions', 'admin', 'verified',
            'email_verified_at', 'password', 'api_key', 'secret',
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

        // Check for enumeration attacks
        $enumerationResult = $this->detectEnumeration($request, $context);
        if ($enumerationResult) {
            $threats[] = $enumerationResult;
        }

        // Check for GraphQL abuse
        if ($this->isGraphQLRequest($request)) {
            $graphqlThreats = $this->detectGraphQLAbuse($request);
            $threats = array_merge($threats, $graphqlThreats);
        }

        // Check for parameter pollution
        $pollutionResult = $this->detectParameterPollution($request);
        if ($pollutionResult) {
            $threats[] = $pollutionResult;
        }

        // Check for mass assignment attempts
        $massAssignmentResult = $this->detectMassAssignment($request);
        if ($massAssignmentResult) {
            $threats[] = $massAssignmentResult;
        }

        // Check for pagination abuse
        $paginationResult = $this->detectPaginationAbuse($request);
        if ($paginationResult) {
            $threats[] = $paginationResult;
        }

        // Check for API versioning exploits
        $versioningResult = $this->detectVersioningExploit($request);
        if ($versioningResult) {
            $threats[] = $versioningResult;
        }

        $metadata['threats_detected'] = count($threats);
        $metadata['is_graphql'] = $this->isGraphQLRequest($request);

        if (!empty($threats)) {
            return GuardResult::fail($this->getName(), $threats)
                ->withMetadata($metadata);
        }

        return GuardResult::pass($this->getName())
            ->withMetadata($metadata);
    }

    /**
     * Detect enumeration attacks.
     */
    private function detectEnumeration(object $request, RuntimeContext $context): ?array
    {
        $ip = $request->ip();
        $path = $request->path();
        $cacheKey = "api_abuse:enum:{$ip}:{$this->normalizePathForEnum($path)}";

        // Track sequential numeric parameter access
        $numericParams = $this->extractNumericParams($request);

        if (empty($numericParams)) {
            return null;
        }

        $history = Cache::get($cacheKey, []);
        $now = time();

        // Add current params to history
        foreach ($numericParams as $param => $value) {
            $history[$param][] = [
                'value' => $value,
                'time' => $now,
            ];
        }

        // Clean old entries
        foreach ($history as $param => $entries) {
            $history[$param] = array_filter($entries, function ($entry) use ($now) {
                return ($now - $entry['time']) < $this->sequentialRequestWindow;
            });
        }

        Cache::put($cacheKey, $history, $this->sequentialRequestWindow);

        // Check for sequential patterns
        foreach ($history as $param => $entries) {
            if (count($entries) >= $this->enumerationThreshold) {
                $values = array_column($entries, 'value');
                if ($this->isSequentialPattern($values)) {
                    return [
                        'type' => 'enumeration_attack',
                        'severity' => 'high',
                        'message' => "Sequential enumeration detected on parameter: {$param}",
                        'details' => [
                            'parameter' => $param,
                            'request_count' => count($entries),
                            'pattern' => 'sequential',
                            'sample_values' => array_slice($values, -5),
                        ],
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Normalize path for enumeration tracking.
     */
    private function normalizePathForEnum(string $path): string
    {
        // Replace numeric segments with placeholder
        return preg_replace('/\/\d+/', '/{id}', $path);
    }

    /**
     * Extract numeric parameters from request.
     */
    private function extractNumericParams(object $request): array
    {
        $numeric = [];
        $params = array_merge(
            $request->query() ?? [],
            $request->route()?->parameters() ?? []
        );

        foreach ($params as $key => $value) {
            if (is_numeric($value)) {
                $numeric[$key] = (int)$value;
            }
        }

        return $numeric;
    }

    /**
     * Check if values follow a sequential pattern.
     */
    private function isSequentialPattern(array $values): bool
    {
        if (count($values) < 3) {
            return false;
        }

        sort($values);
        $differences = [];

        for ($i = 1; $i < count($values); $i++) {
            $differences[] = $values[$i] - $values[$i - 1];
        }

        // Check for consistent differences (sequential)
        $uniqueDiffs = array_unique($differences);
        if (count($uniqueDiffs) <= 2 && in_array(1, $uniqueDiffs)) {
            return true;
        }

        return false;
    }

    /**
     * Check if request is GraphQL.
     */
    private function isGraphQLRequest(object $request): bool
    {
        $path = $request->path();
        $contentType = $request->header('Content-Type', '');

        return str_contains($path, 'graphql') ||
               str_contains($contentType, 'application/graphql');
    }

    /**
     * Detect GraphQL-specific abuse.
     */
    private function detectGraphQLAbuse(object $request): array
    {
        $threats = [];
        $body = $request->getContent();
        $data = json_decode($body, true);

        if (!$data) {
            return $threats;
        }

        $query = $data['query'] ?? '';

        // Check query depth
        $depth = $this->calculateGraphQLDepth($query);
        if ($depth > $this->maxGraphQLDepth) {
            $threats[] = [
                'type' => 'graphql_deep_query',
                'severity' => 'high',
                'message' => "GraphQL query depth ({$depth}) exceeds maximum ({$this->maxGraphQLDepth})",
                'details' => [
                    'depth' => $depth,
                    'max_allowed' => $this->maxGraphQLDepth,
                ],
            ];
        }

        // Check for batch operations
        if (isset($data[0]) && is_array($data[0])) {
            $batchSize = count($data);
            if ($batchSize > $this->maxBatchOperations) {
                $threats[] = [
                    'type' => 'graphql_batch_abuse',
                    'severity' => 'medium',
                    'message' => "GraphQL batch size ({$batchSize}) exceeds maximum ({$this->maxBatchOperations})",
                    'details' => [
                        'batch_size' => $batchSize,
                        'max_allowed' => $this->maxBatchOperations,
                    ],
                ];
            }
        }

        // Check for introspection abuse
        if ($this->hasExcessiveIntrospection($query)) {
            $threats[] = [
                'type' => 'graphql_introspection_abuse',
                'severity' => 'medium',
                'message' => 'Excessive GraphQL introspection detected',
                'details' => [
                    'query_preview' => substr($query, 0, 200),
                ],
            ];
        }

        // Check field count
        $fieldCount = $this->countGraphQLFields($query);
        if ($fieldCount > $this->maxFieldsPerQuery) {
            $threats[] = [
                'type' => 'graphql_field_abuse',
                'severity' => 'medium',
                'message' => "Excessive field selection ({$fieldCount} fields)",
                'details' => [
                    'field_count' => $fieldCount,
                    'max_allowed' => $this->maxFieldsPerQuery,
                ],
            ];
        }

        return $threats;
    }

    /**
     * Calculate GraphQL query depth.
     */
    private function calculateGraphQLDepth(string $query): int
    {
        $depth = 0;
        $maxDepth = 0;

        for ($i = 0; $i < strlen($query); $i++) {
            if ($query[$i] === '{') {
                $depth++;
                $maxDepth = max($maxDepth, $depth);
            } elseif ($query[$i] === '}') {
                $depth--;
            }
        }

        return $maxDepth;
    }

    /**
     * Check for excessive introspection queries.
     */
    private function hasExcessiveIntrospection(string $query): bool
    {
        $introspectionKeywords = ['__schema', '__type', '__typename', '__directive', '__field'];
        $count = 0;

        foreach ($introspectionKeywords as $keyword) {
            $count += substr_count($query, $keyword);
        }

        return $count > 5;
    }

    /**
     * Count fields in GraphQL query.
     */
    private function countGraphQLFields(string $query): int
    {
        // Simple estimation: count identifiers followed by optional arguments
        preg_match_all('/\b[a-zA-Z_][a-zA-Z0-9_]*\s*(?:\([^)]*\))?\s*(?={|\s)/', $query, $matches);
        return count($matches[0]);
    }

    /**
     * Detect parameter pollution.
     */
    private function detectParameterPollution(object $request): ?array
    {
        $queryString = $request->server('QUERY_STRING', '');
        $duplicates = [];

        // Parse query string manually to find duplicates
        parse_str($queryString, $parsed);
        preg_match_all('/([^&=]+)=/', $queryString, $matches);

        $paramCounts = array_count_values($matches[1]);
        foreach ($paramCounts as $param => $count) {
            if ($count > 1) {
                $duplicates[$param] = $count;
            }
        }

        if (!empty($duplicates)) {
            return [
                'type' => 'parameter_pollution',
                'severity' => 'medium',
                'message' => 'HTTP Parameter Pollution detected',
                'details' => [
                    'duplicated_parameters' => $duplicates,
                ],
            ];
        }

        return null;
    }

    /**
     * Detect mass assignment attempts.
     */
    private function detectMassAssignment(object $request): ?array
    {
        if (!in_array($request->method(), ['POST', 'PUT', 'PATCH'])) {
            return null;
        }

        $input = $request->all();
        $suspiciousFound = [];

        foreach ($this->sensitiveParameters as $param) {
            if ($this->hasParameterRecursive($input, $param)) {
                $suspiciousFound[] = $param;
            }
        }

        if (!empty($suspiciousFound)) {
            return [
                'type' => 'mass_assignment_attempt',
                'severity' => 'high',
                'message' => 'Mass assignment attack detected',
                'details' => [
                    'suspicious_parameters' => $suspiciousFound,
                ],
            ];
        }

        return null;
    }

    /**
     * Check for parameter recursively in nested arrays.
     */
    private function hasParameterRecursive(array $data, string $param): bool
    {
        if (array_key_exists($param, $data)) {
            return true;
        }

        foreach ($data as $value) {
            if (is_array($value) && $this->hasParameterRecursive($value, $param)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect pagination abuse.
     */
    private function detectPaginationAbuse(object $request): ?array
    {
        $paginationParams = ['limit', 'per_page', 'page_size', 'size', 'count', 'take', 'first', 'last'];
        $input = array_merge($request->query() ?? [], $request->all());

        foreach ($paginationParams as $param) {
            if (isset($input[$param])) {
                $value = (int)$input[$param];
                if ($value > $this->maxPageSize) {
                    return [
                        'type' => 'pagination_abuse',
                        'severity' => 'medium',
                        'message' => "Excessive pagination size requested: {$value}",
                        'details' => [
                            'parameter' => $param,
                            'requested' => $value,
                            'max_allowed' => $this->maxPageSize,
                        ],
                    ];
                }
            }
        }

        // Check for negative pagination (skip abuse)
        $skipParams = ['offset', 'skip', 'page'];
        foreach ($skipParams as $param) {
            if (isset($input[$param])) {
                $value = (int)$input[$param];
                if ($value < 0) {
                    return [
                        'type' => 'pagination_abuse',
                        'severity' => 'low',
                        'message' => "Negative pagination value: {$param}={$value}",
                        'details' => [
                            'parameter' => $param,
                            'value' => $value,
                        ],
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Detect API versioning exploits.
     */
    private function detectVersioningExploit(object $request): ?array
    {
        $path = $request->path();
        $headers = [
            'Accept-Version' => $request->header('Accept-Version'),
            'Api-Version' => $request->header('Api-Version'),
            'X-Api-Version' => $request->header('X-Api-Version'),
        ];

        // Check for suspicious version patterns
        $suspiciousVersions = [];

        // Path version
        if (preg_match('/\/v(\d+(?:\.\d+)*|latest|beta|alpha|dev|internal|admin)/i', $path, $matches)) {
            $version = $matches[1];
            if (in_array(strtolower($version), ['internal', 'admin', 'dev', 'debug'])) {
                $suspiciousVersions['path'] = $version;
            }
        }

        // Header versions
        foreach ($headers as $header => $value) {
            if ($value && preg_match('/(internal|admin|dev|debug)/i', $value)) {
                $suspiciousVersions[$header] = $value;
            }
        }

        if (!empty($suspiciousVersions)) {
            return [
                'type' => 'api_versioning_exploit',
                'severity' => 'medium',
                'message' => 'Suspicious API version access attempt',
                'details' => [
                    'suspicious_versions' => $suspiciousVersions,
                ],
            ];
        }

        return null;
    }

    public function getName(): string
    {
        return 'api_abuse';
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getPriority(): int
    {
        return 90;
    }

    public function getSeverity(): string
    {
        return 'high';
    }
}
