<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Guards;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Detects potential SQL injection attacks.
 *
 * Uses tiered inspection with quick scan patterns for fast detection
 * and deep inspection patterns for thorough analysis.
 */
class SqlInjectionGuard extends AbstractGuard
{
    /**
     * Quick scan patterns - fast, high-confidence checks.
     *
     * @var array<string>
     */
    protected array $quickPatterns = ['basic_injection', 'comment_injection'];

    /**
     * Deep inspection patterns - thorough analysis.
     *
     * @var array<string>
     */
    protected array $deepPatterns = ['basic_injection', 'comment_injection', 'union_based', 'boolean_based', 'time_based', 'stacked_queries'];

    public function getName(): string
    {
        return 'sql-injection';
    }

    /**
     * {@inheritdoc}
     */
    protected function getPatterns(): array
    {
        return array_merge($this->getDefaultPatterns(), $this->getConfig('patterns', []));
    }

    /**
     * Default SQL injection patterns.
     *
     * @return array<string, array<string>>
     */
    protected function getDefaultPatterns(): array
    {
        return [
            'basic_injection' => [
                '\bUNION\s+SELECT\b',
                '\bSELECT\s+\*\s+FROM\b',
                '\bINSERT\s+INTO\b',
                '\bDELETE\s+FROM\b',
                '\bDROP\s+TABLE\b',
                '\bDROP\s+DATABASE\b',
                '\bUPDATE\s+\w+\s+SET\b',
                '\bTRUNCATE\s+TABLE\b',
                '\bALTER\s+TABLE\b',
                '\bEXEC\s*\(',
                '\bEXECUTE\s*\(',
            ],

            'comment_injection' => [
                '--\s*$',
                '--\s+',
                '#\s*$',
                '/\*.*?\*/',
                '/\*!',
            ],

            'union_based' => [
                '\bUNION\s+ALL\s+SELECT\b',
                '\bUNION\s+SELECT\s+NULL\b',
                '\bSELECT\s+@@version\b',
                '\bSELECT\s+user\s*\(\)',
                '\bSELECT\s+database\s*\(\)',
                '\bINFORMATION_SCHEMA\.',
                '\bSYS\.(TABLES|COLUMNS)\b',
            ],

            'boolean_based' => [
                '\'\s*(OR|AND)\s*\'?\d*\'?\s*=\s*\'?\d*',
                '\'\s*(OR|AND)\s+\d+\s*=\s*\d+',
                '\bOR\s+1\s*=\s*1\b',
                '\bAND\s+1\s*=\s*1\b',
                '\bOR\s+\'a\'\s*=\s*\'a\'',
                '\bOR\s+TRUE\b',
                '\bOR\s+NOT\s+FALSE\b',
            ],

            'time_based' => [
                '\bSLEEP\s*\(\s*\d+\s*\)',
                '\bBENCHMARK\s*\(',
                '\bWAITFOR\s+DELAY\b',
                '\bPG_SLEEP\s*\(',
                '\bDBMS_PIPE\.RECEIVE_MESSAGE\b',
            ],

            'stacked_queries' => [
                ';\s*SELECT\b',
                ';\s*INSERT\b',
                ';\s*UPDATE\b',
                ';\s*DELETE\b',
                ';\s*DROP\b',
                ';\s*EXEC\b',
            ],

            'error_based' => [
                '\bEXTRACTVALUE\s*\(',
                '\bUPDATEXML\s*\(',
                '\bEXP\s*\(\s*~\s*\(',
                '\bGROUP\s+BY\s+.*\s+HAVING\b',
                'CONVERT\s*\(\s*INT\s*,',
                'CAST\s*\(\s*.*\s+AS\s+INT\s*\)',
            ],

            'out_of_band' => [
                '\bLOAD_FILE\s*\(',
                '\bINTO\s+OUTFILE\b',
                '\bINTO\s+DUMPFILE\b',
                '\bUTL_HTTP\.',
                '\bDBMS_LDAP\.',
            ],

            'encoding_bypass' => [
                '0x[0-9a-f]{8,}',
                'CHAR\s*\(\s*\d+\s*\)',
                'CHR\s*\(\s*\d+\s*\)',
                '\bASCII\s*\(',
                '\bORD\s*\(',
                '\bCONCAT\s*\(',
                '\bCONCAT_WS\s*\(',
            ],
        ];
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        $normalized = $this->normalizeInput($input);

        if ($normalized === '') {
            return $this->pass('Empty input');
        }

        // Check all compiled patterns
        foreach ($this->compiledPatterns as $patternName => $pattern) {
            if (preg_match($pattern, $normalized, $matches)) {
                return $this->createSqlInjectionResult($patternName, $matches[0], $normalized);
            }
        }

        // Additional heuristic checks
        if ($this->hasQuoteImbalance($normalized)) {
            return $this->threat(
                'Suspicious quote pattern detected',
                ThreatLevel::MEDIUM,
                ['type' => 'quote_imbalance', 'input_sample' => substr($normalized, 0, 200)]
            );
        }

        if ($this->hasEncodedSqlKeywords($normalized)) {
            return $this->threat(
                'Encoded SQL keywords detected',
                ThreatLevel::HIGH,
                ['type' => 'encoded_sql', 'input_sample' => substr($normalized, 0, 200)]
            );
        }

        return $this->pass();
    }

    /**
     * Normalize input for inspection.
     */
    protected function normalizeInput(mixed $input): string
    {
        if (is_string($input)) {
            return $this->prepareForInspection($input);
        }

        if (is_array($input)) {
            return $this->prepareForInspection($this->flattenArray($input));
        }

        if (is_object($input) && method_exists($input, '__toString')) {
            return $this->prepareForInspection((string) $input);
        }

        return '';
    }

    /**
     * Prepare string for inspection.
     */
    protected function prepareForInspection(string $input): string
    {
        // URL decode
        $decoded = urldecode($input);

        // Normalize whitespace
        $decoded = preg_replace('/\s+/', ' ', $decoded) ?? $decoded;

        return $decoded;
    }

    /**
     * Flatten array to string.
     */
    protected function flattenArray(array $data, int $depth = 0): string
    {
        if ($depth > 10) {
            return '';
        }

        $parts = [];
        foreach ($data as $value) {
            if (is_string($value)) {
                $parts[] = $value;
            } elseif (is_array($value)) {
                $parts[] = $this->flattenArray($value, $depth + 1);
            }
        }

        return implode(' ', $parts);
    }

    /**
     * Check for quote imbalance (common in SQL injection).
     */
    protected function hasQuoteImbalance(string $input): bool
    {
        $singleQuotes = substr_count($input, "'") - substr_count($input, "\\'");
        $doubleQuotes = substr_count($input, '"') - substr_count($input, '\\"');

        // Odd number of quotes can indicate injection attempt
        return ($singleQuotes % 2 !== 0) || ($doubleQuotes % 2 !== 0);
    }

    /**
     * Check for encoded SQL keywords.
     */
    protected function hasEncodedSqlKeywords(string $input): bool
    {
        // Check for hex-encoded SQL keywords
        $hexPatterns = [
            '0x53454c454354', // SELECT
            '0x554e494f4e',   // UNION
            '0x44524f50',     // DROP
            '0x494e53455254', // INSERT
        ];

        foreach ($hexPatterns as $pattern) {
            if (stripos($input, $pattern) !== false) {
                return true;
            }
        }

        // Check for URL-encoded keywords
        $urlEncodedKeywords = [
            '%53%45%4c%45%43%54', // SELECT
            '%55%4e%49%4f%4e',    // UNION
        ];

        foreach ($urlEncodedKeywords as $keyword) {
            if (stripos($input, $keyword) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Create SQL injection result.
     */
    protected function createSqlInjectionResult(string $patternName, string $matched, string $fullInput): GuardResultInterface
    {
        $level = match ($patternName) {
            'basic_injection', 'stacked_queries', 'out_of_band' => ThreatLevel::CRITICAL,
            'union_based', 'time_based', 'error_based' => ThreatLevel::HIGH,
            'boolean_based', 'comment_injection', 'encoding_bypass' => ThreatLevel::HIGH,
            default => ThreatLevel::MEDIUM,
        };

        return $this->threat(
            "SQL injection attempt detected: {$patternName}",
            $level,
            [
                'pattern' => $patternName,
                'matched' => substr($matched, 0, 100),
                'input_sample' => substr($fullInput, 0, 200),
            ]
        );
    }
}
