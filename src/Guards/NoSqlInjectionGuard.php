<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Detects NoSQL Injection attacks.
 *
 * Targets MongoDB, DynamoDB, and other NoSQL databases.
 */
class NoSqlInjectionGuard extends AbstractGuard
{
    protected array $quickPatterns = ['mongo_operators', 'query_operators'];

    public function getName(): string
    {
        return 'nosql-injection';
    }

    protected function getPatterns(): array
    {
        return [
            'mongo_operators' => [
                '\$where',
                '\$regex',
                '\$ne',
                '\$gt',
                '\$gte',
                '\$lt',
                '\$lte',
                '\$in',
                '\$nin',
                '\$or',
                '\$and',
                '\$not',
                '\$nor',
                '\$exists',
                '\$type',
                '\$mod',
                '\$all',
                '\$size',
                '\$elemMatch',
            ],
            'query_operators' => [
                '\$eq',
                '\$expr',
                '\$jsonSchema',
                '\$text',
                '\$search',
                '\$geoWithin',
                '\$geoIntersects',
                '\$near',
            ],
            'aggregation' => [
                '\$group',
                '\$match',
                '\$project',
                '\$lookup',
                '\$unwind',
                '\$sort',
                '\$limit',
                '\$skip',
                '\$out',
                '\$merge',
            ],
            'javascript_execution' => [
                '\$function',
                '\$accumulator',
                'mapReduce',
                'function\s*\(',
                'db\.\w+\.\w+',
            ],
            'special_chars' => [
                '[\x00]',
                '\\x00',
            ],
        ];
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        // Check string input
        if (is_string($input)) {
            return $this->inspectString($input);
        }

        // Check array input (more dangerous for NoSQL)
        if (is_array($input)) {
            return $this->inspectArray($input);
        }

        return $this->pass();
    }

    /**
     * Inspect string for NoSQL injection patterns.
     */
    protected function inspectString(string $input): GuardResultInterface
    {
        foreach ($this->compiledPatterns as $patternName => $pattern) {
            if (preg_match($pattern, $input, $matches)) {
                return $this->createResult($patternName, $matches[0], $input);
            }
        }

        // Check for JSON-encoded operators
        if ($this->hasJsonEncodedOperator($input)) {
            return $this->threat(
                'JSON-encoded NoSQL operator detected',
                ThreatLevel::HIGH,
                ['type' => 'json_encoded', 'input_sample' => substr($input, 0, 200)]
            );
        }

        return $this->pass();
    }

    /**
     * Inspect array for NoSQL injection (operator injection).
     */
    protected function inspectArray(array $input, int $depth = 0): GuardResultInterface
    {
        if ($depth > 10) {
            return $this->pass();
        }

        foreach ($input as $key => $value) {
            // Check if key is a MongoDB operator
            if (is_string($key) && str_starts_with($key, '$')) {
                return $this->threat(
                    'NoSQL operator injection detected',
                    ThreatLevel::CRITICAL,
                    [
                        'operator' => $key,
                        'type' => 'operator_injection',
                        'value_type' => gettype($value),
                    ]
                );
            }

            // Check string values
            if (is_string($value)) {
                $result = $this->inspectString($value);
                if ($result->failed()) {
                    return $result;
                }
            }

            // Recurse into nested arrays
            if (is_array($value)) {
                $result = $this->inspectArray($value, $depth + 1);
                if ($result->failed()) {
                    return $result;
                }
            }
        }

        return $this->pass();
    }

    /**
     * Check for JSON-encoded NoSQL operators.
     */
    protected function hasJsonEncodedOperator(string $input): bool
    {
        // Try to decode JSON
        $decoded = json_decode($input, true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) {
            return false;
        }

        return $this->arrayHasOperator($decoded);
    }

    /**
     * Recursively check array for operators.
     */
    protected function arrayHasOperator(array $data, int $depth = 0): bool
    {
        if ($depth > 5) {
            return false;
        }

        foreach ($data as $key => $value) {
            if (is_string($key) && str_starts_with($key, '$')) {
                return true;
            }

            if (is_array($value) && $this->arrayHasOperator($value, $depth + 1)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Create result for pattern match.
     */
    protected function createResult(string $patternName, string $matched, string $input): GuardResultInterface
    {
        $level = match ($patternName) {
            'javascript_execution', 'mongo_operators' => ThreatLevel::CRITICAL,
            'query_operators', 'aggregation' => ThreatLevel::HIGH,
            default => ThreatLevel::MEDIUM,
        };

        return $this->threat(
            "NoSQL injection attempt: {$patternName}",
            $level,
            [
                'pattern' => $patternName,
                'matched' => $matched,
                'input_sample' => substr($input, 0, 200),
            ]
        );
    }
}
