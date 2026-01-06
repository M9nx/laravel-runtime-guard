<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Detects GraphQL-specific attacks.
 *
 * Protects against query depth abuse, complexity attacks, and introspection probing.
 */
class GraphQLGuard extends AbstractGuard
{
    protected int $maxDepth;
    protected int $maxComplexity;
    protected bool $allowIntrospection;
    protected int $maxAliases;
    protected int $maxDirectives;

    public function getName(): string
    {
        return 'graphql';
    }

    public function onBoot(): void
    {
        parent::onBoot();

        $this->maxDepth = (int) config('runtime-guard.guards.graphql.max_depth', 10);
        $this->maxComplexity = (int) config('runtime-guard.guards.graphql.max_complexity', 100);
        $this->allowIntrospection = (bool) config('runtime-guard.guards.graphql.allow_introspection', false);
        $this->maxAliases = (int) config('runtime-guard.guards.graphql.max_aliases', 10);
        $this->maxDirectives = (int) config('runtime-guard.guards.graphql.max_directives', 5);
    }

    protected function getPatterns(): array
    {
        return [
            'introspection' => [
                '__schema',
                '__type',
                '__typename',
            ],
            'batch_attack' => [
                'alias\d+:',
                '[\w]+\d+\s*:',
            ],
            'directive_abuse' => [
                '@skip',
                '@include',
                '@deprecated',
                '@defer',
                '@stream',
            ],
        ];
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        if (!is_string($input)) {
            return $this->pass();
        }

        // Check if this looks like a GraphQL query
        if (!$this->isGraphQLQuery($input)) {
            return $this->pass();
        }

        // Check introspection
        if (!$this->allowIntrospection && $this->hasIntrospection($input)) {
            return $this->threat(
                'GraphQL introspection blocked',
                ThreatLevel::MEDIUM,
                [
                    'type' => 'introspection',
                    'query_sample' => substr($input, 0, 200),
                ]
            );
        }

        // Check query depth
        $depth = $this->calculateDepth($input);
        if ($depth > $this->maxDepth) {
            return $this->threat(
                'GraphQL query depth exceeded',
                ThreatLevel::HIGH,
                [
                    'type' => 'depth_abuse',
                    'depth' => $depth,
                    'max_allowed' => $this->maxDepth,
                ]
            );
        }

        // Check query complexity
        $complexity = $this->calculateComplexity($input);
        if ($complexity > $this->maxComplexity) {
            return $this->threat(
                'GraphQL query complexity exceeded',
                ThreatLevel::HIGH,
                [
                    'type' => 'complexity_abuse',
                    'complexity' => $complexity,
                    'max_allowed' => $this->maxComplexity,
                ]
            );
        }

        // Check alias count (batching attack)
        $aliasCount = $this->countAliases($input);
        if ($aliasCount > $this->maxAliases) {
            return $this->threat(
                'GraphQL alias abuse detected',
                ThreatLevel::HIGH,
                [
                    'type' => 'alias_abuse',
                    'alias_count' => $aliasCount,
                    'max_allowed' => $this->maxAliases,
                ]
            );
        }

        // Check directive count
        $directiveCount = $this->countDirectives($input);
        if ($directiveCount > $this->maxDirectives) {
            return $this->threat(
                'GraphQL directive abuse detected',
                ThreatLevel::MEDIUM,
                [
                    'type' => 'directive_abuse',
                    'directive_count' => $directiveCount,
                    'max_allowed' => $this->maxDirectives,
                ]
            );
        }

        // Check for field duplication attack
        if ($this->hasFieldDuplication($input)) {
            return $this->threat(
                'GraphQL field duplication attack detected',
                ThreatLevel::HIGH,
                [
                    'type' => 'field_duplication',
                    'query_sample' => substr($input, 0, 200),
                ]
            );
        }

        return $this->pass();
    }

    /**
     * Check if input looks like a GraphQL query.
     */
    protected function isGraphQLQuery(string $input): bool
    {
        $trimmed = trim($input);

        // Check for common GraphQL patterns
        return preg_match('/^(query|mutation|subscription|fragment|\{)/i', $trimmed) === 1
            || str_contains($input, '{')
            && (str_contains($input, '}') || preg_match('/\w+\s*\(/', $input));
    }

    /**
     * Check for introspection queries.
     */
    protected function hasIntrospection(string $input): bool
    {
        return str_contains($input, '__schema')
            || str_contains($input, '__type')
            || preg_match('/__\w+/', $input) === 1;
    }

    /**
     * Calculate query depth by counting nested braces.
     */
    protected function calculateDepth(string $input): int
    {
        $maxDepth = 0;
        $currentDepth = 0;

        for ($i = 0, $len = strlen($input); $i < $len; $i++) {
            if ($input[$i] === '{') {
                $currentDepth++;
                $maxDepth = max($maxDepth, $currentDepth);
            } elseif ($input[$i] === '}') {
                $currentDepth = max(0, $currentDepth - 1);
            }
        }

        return $maxDepth;
    }

    /**
     * Calculate query complexity based on fields and arguments.
     */
    protected function calculateComplexity(string $input): int
    {
        $complexity = 0;

        // Count fields (words followed by { or arguments)
        $complexity += preg_match_all('/\w+\s*[\({]/', $input);

        // Count nested levels (each level multiplies complexity)
        $depth = $this->calculateDepth($input);
        $complexity += $depth * 5;

        // Count arguments (each argument adds complexity)
        $complexity += preg_match_all('/\w+\s*:\s*["\'\w]/', $input);

        // Count list arguments (exponential cost)
        $complexity += preg_match_all('/\[\s*\w/', $input) * 3;

        return $complexity;
    }

    /**
     * Count field aliases in the query.
     */
    protected function countAliases(string $input): int
    {
        // Aliases look like: aliasName: fieldName
        preg_match_all('/\w+\s*:\s*\w+\s*[\({]/', $input, $matches);

        return count($matches[0] ?? []);
    }

    /**
     * Count directives in the query.
     */
    protected function countDirectives(string $input): int
    {
        preg_match_all('/@\w+/', $input, $matches);

        return count($matches[0] ?? []);
    }

    /**
     * Check for field duplication attack (same field many times).
     */
    protected function hasFieldDuplication(string $input): bool
    {
        // Extract field names
        preg_match_all('/(\w+)\s*[\({]/', $input, $matches);
        $fields = $matches[1] ?? [];

        if (empty($fields)) {
            return false;
        }

        // Count occurrences
        $counts = array_count_values($fields);

        // Flag if any field appears more than 5 times
        foreach ($counts as $count) {
            if ($count > 5) {
                return true;
            }
        }

        return false;
    }
}
