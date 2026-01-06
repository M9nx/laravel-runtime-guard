<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Support;

/**
 * Request fingerprint memoization.
 *
 * Computes request fingerprint once and shares across all guards.
 * Avoids redundant hashing when multiple guards need the same fingerprint.
 */
class RequestFingerprint
{
    private ?string $fingerprint = null;
    private ?string $inputHash = null;
    private ?string $contextHash = null;
    private ?array $components = null;

    private string $algorithm;
    private bool $includeHeaders;
    private array $headerWhitelist;

    public function __construct(array $config = [])
    {
        $this->algorithm = $config['algorithm'] ?? 'xxh128';
        $this->includeHeaders = $config['include_headers'] ?? true;
        $this->headerWhitelist = $config['header_whitelist'] ?? [
            'user-agent',
            'accept',
            'accept-language',
            'accept-encoding',
            'content-type',
        ];
    }

    /**
     * Create from configuration.
     */
    public static function fromConfig(array $config): self
    {
        return new self($config);
    }

    /**
     * Get or compute the full request fingerprint.
     */
    public function getFingerprint(mixed $input, InspectionContext $context): string
    {
        if ($this->fingerprint !== null) {
            return $this->fingerprint;
        }

        $components = $this->getComponents($input, $context);
        $this->fingerprint = $this->hash(implode('|', $components));

        return $this->fingerprint;
    }

    /**
     * Get or compute input-only hash.
     */
    public function getInputHash(mixed $input): string
    {
        if ($this->inputHash !== null) {
            return $this->inputHash;
        }

        $this->inputHash = $this->hash($this->serializeInput($input));

        return $this->inputHash;
    }

    /**
     * Get or compute context-only hash.
     */
    public function getContextHash(InspectionContext $context): string
    {
        if ($this->contextHash !== null) {
            return $this->contextHash;
        }

        $parts = [
            $context->ip() ?? '',
            $context->path() ?? '',
            $context->method() ?? '',
        ];

        if ($this->includeHeaders) {
            $headers = $context->getMeta('headers', []);
            foreach ($this->headerWhitelist as $header) {
                $parts[] = $headers[$header] ?? '';
            }
        }

        $this->contextHash = $this->hash(implode('|', $parts));

        return $this->contextHash;
    }

    /**
     * Get fingerprint components.
     */
    public function getComponents(mixed $input, InspectionContext $context): array
    {
        if ($this->components !== null) {
            return $this->components;
        }

        $this->components = [
            'input' => $this->getInputHash($input),
            'context' => $this->getContextHash($context),
            'path' => $context->path() ?? '',
            'method' => $context->method() ?? '',
        ];

        return $this->components;
    }

    /**
     * Check if fingerprint matches.
     */
    public function matches(string $fingerprint): bool
    {
        return $this->fingerprint !== null && hash_equals($this->fingerprint, $fingerprint);
    }

    /**
     * Reset memoized values (call between requests).
     */
    public function reset(): void
    {
        $this->fingerprint = null;
        $this->inputHash = null;
        $this->contextHash = null;
        $this->components = null;
    }

    /**
     * Get short fingerprint (first 16 chars).
     */
    public function getShortFingerprint(mixed $input, InspectionContext $context): string
    {
        return substr($this->getFingerprint($input, $context), 0, 16);
    }

    /**
     * Compute hash using configured algorithm.
     */
    private function hash(string $data): string
    {
        // Use xxHash if available (PHP 8.1+)
        if ($this->algorithm === 'xxh128' && function_exists('hash') && in_array('xxh128', hash_algos())) {
            return hash('xxh128', $data);
        }

        if ($this->algorithm === 'xxh3' && function_exists('hash') && in_array('xxh3', hash_algos())) {
            return hash('xxh3', $data);
        }

        // Fallback to SHA256 (fast enough for most cases)
        return hash('sha256', $data);
    }

    /**
     * Serialize input for hashing.
     */
    private function serializeInput(mixed $input): string
    {
        if (is_string($input)) {
            return $input;
        }

        if (is_array($input)) {
            return $this->serializeArray($input);
        }

        if (is_object($input)) {
            if (method_exists($input, '__toString')) {
                return (string) $input;
            }
            return $this->serializeArray((array) $input);
        }

        return serialize($input);
    }

    /**
     * Serialize array with consistent ordering.
     */
    private function serializeArray(array $data, int $depth = 0): string
    {
        if ($depth > 10) {
            return '[max_depth]';
        }

        ksort($data);
        $parts = [];

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $parts[] = $key . ':' . $this->serializeArray($value, $depth + 1);
            } elseif (is_object($value)) {
                $parts[] = $key . ':[object:' . get_class($value) . ']';
            } elseif (is_bool($value)) {
                $parts[] = $key . ':' . ($value ? 'true' : 'false');
            } elseif (is_null($value)) {
                $parts[] = $key . ':null';
            } else {
                $parts[] = $key . ':' . $value;
            }
        }

        return '{' . implode(',', $parts) . '}';
    }

    /**
     * Get statistics about fingerprint computation.
     */
    public function stats(): array
    {
        return [
            'fingerprint_computed' => $this->fingerprint !== null,
            'input_hash_computed' => $this->inputHash !== null,
            'context_hash_computed' => $this->contextHash !== null,
            'algorithm' => $this->algorithm,
        ];
    }
}
