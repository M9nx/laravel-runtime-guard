<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Analytics;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;

/**
 * Attack Fingerprinting.
 *
 * Generates unique fingerprints for attack patterns to identify repeat attackers.
 */
class AttackFingerprinter
{
    protected array $fingerprintCache = [];
    protected int $cacheLimit = 10000;

    /**
     * Generate a fingerprint for an attack.
     */
    public function fingerprint(
        GuardResultInterface $result,
        array $context = []
    ): AttackFingerprint {
        $components = $this->extractComponents($result, $context);
        $hash = $this->generateHash($components);

        return new AttackFingerprint(
            hash: $hash,
            components: $components,
            confidence: $this->calculateConfidence($components),
            timestamp: time()
        );
    }

    /**
     * Extract fingerprint components from result and context.
     */
    protected function extractComponents(GuardResultInterface $result, array $context): array
    {
        $components = [
            // Attack characteristics
            'guard' => $context['guard'] ?? 'unknown',
            'threat_level' => $result->getThreatLevel()?->value ?? 0,
            'pattern_hash' => $this->hashPattern($result->getDetails()['matched'] ?? ''),

            // Request characteristics
            'method' => strtoupper($context['method'] ?? 'GET'),
            'path_pattern' => $this->normalizePath($context['path'] ?? '/'),
            'content_type' => $context['content_type'] ?? '',

            // Behavioral characteristics
            'input_size_bucket' => $this->sizeBucket($context['input_size'] ?? 0),
            'parameter_count' => $context['parameter_count'] ?? 0,
            'encoding_layers' => $this->detectEncodingLayers($result->getDetails()['input_sample'] ?? ''),
        ];

        // Add optional components
        if (isset($context['user_agent'])) {
            $components['ua_family'] = $this->extractUaFamily($context['user_agent']);
        }

        if (isset($context['headers'])) {
            $components['header_signature'] = $this->hashHeaders($context['headers']);
        }

        return $components;
    }

    /**
     * Generate hash from components.
     */
    protected function generateHash(array $components): string
    {
        // Use stable subset for core fingerprint
        $coreComponents = [
            $components['guard'],
            $components['pattern_hash'],
            $components['method'],
            $components['path_pattern'],
            $components['encoding_layers'],
        ];

        return hash('xxh128', implode('|', $coreComponents));
    }

    /**
     * Hash the attack pattern.
     */
    protected function hashPattern(string $pattern): string
    {
        if (empty($pattern)) {
            return '';
        }

        // Normalize pattern before hashing
        $normalized = preg_replace('/[0-9]+/', 'N', $pattern); // Replace numbers
        $normalized = preg_replace('/\s+/', ' ', $normalized); // Normalize whitespace

        return hash('xxh64', $normalized);
    }

    /**
     * Normalize path for fingerprinting.
     */
    protected function normalizePath(string $path): string
    {
        // Replace numeric IDs with placeholder
        $normalized = preg_replace('/\/\d+/', '/{id}', $path);

        // Replace UUIDs
        $normalized = preg_replace(
            '/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i',
            '{uuid}',
            $normalized
        );

        return $normalized;
    }

    /**
     * Bucket input size for comparison.
     */
    protected function sizeBucket(int $size): string
    {
        return match (true) {
            $size < 100 => 'tiny',
            $size < 1000 => 'small',
            $size < 10000 => 'medium',
            $size < 100000 => 'large',
            default => 'huge',
        };
    }

    /**
     * Detect encoding layers in input.
     */
    protected function detectEncodingLayers(string $input): int
    {
        $layers = 0;

        // Check for URL encoding
        if (preg_match('/%[0-9A-Fa-f]{2}/', $input)) {
            $layers++;
        }

        // Check for base64
        if (preg_match('/^[A-Za-z0-9+\/]+=*$/', trim($input))) {
            $layers++;
        }

        // Check for HTML encoding
        if (preg_match('/&[a-z]+;|&#[0-9]+;/i', $input)) {
            $layers++;
        }

        // Check for Unicode escapes
        if (preg_match('/\\\\u[0-9A-Fa-f]{4}/', $input)) {
            $layers++;
        }

        return $layers;
    }

    /**
     * Extract User-Agent family.
     */
    protected function extractUaFamily(string $userAgent): string
    {
        $patterns = [
            'curl' => '/curl/i',
            'wget' => '/wget/i',
            'python' => '/python/i',
            'go-http' => '/go-http/i',
            'java' => '/java/i',
            'bot' => '/bot|crawler|spider/i',
            'chrome' => '/chrome/i',
            'firefox' => '/firefox/i',
            'safari' => '/safari/i',
            'edge' => '/edge/i',
        ];

        foreach ($patterns as $family => $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return $family;
            }
        }

        return 'unknown';
    }

    /**
     * Hash relevant headers.
     */
    protected function hashHeaders(array $headers): string
    {
        $relevant = ['accept', 'accept-language', 'accept-encoding', 'connection'];
        $values = [];

        foreach ($relevant as $header) {
            if (isset($headers[$header])) {
                $values[] = $headers[$header];
            }
        }

        return hash('xxh64', implode('|', $values));
    }

    /**
     * Calculate fingerprint confidence score.
     */
    protected function calculateConfidence(array $components): float
    {
        $score = 0;
        $weights = [
            'pattern_hash' => 0.3,
            'guard' => 0.2,
            'path_pattern' => 0.15,
            'encoding_layers' => 0.15,
            'header_signature' => 0.1,
            'ua_family' => 0.1,
        ];

        foreach ($weights as $component => $weight) {
            if (!empty($components[$component])) {
                $score += $weight;
            }
        }

        return min(1.0, $score);
    }

    /**
     * Compare two fingerprints for similarity.
     */
    public function compare(AttackFingerprint $a, AttackFingerprint $b): float
    {
        // Exact match
        if ($a->hash === $b->hash) {
            return 1.0;
        }

        // Component-wise comparison
        $matches = 0;
        $total = 0;
        $weights = [
            'guard' => 3,
            'pattern_hash' => 5,
            'path_pattern' => 2,
            'method' => 1,
            'encoding_layers' => 2,
        ];

        foreach ($weights as $component => $weight) {
            $total += $weight;
            if (($a->components[$component] ?? '') === ($b->components[$component] ?? '')) {
                $matches += $weight;
            }
        }

        return $total > 0 ? $matches / $total : 0;
    }

    /**
     * Find similar fingerprints.
     */
    public function findSimilar(AttackFingerprint $fingerprint, array $candidates, float $threshold = 0.7): array
    {
        $similar = [];

        foreach ($candidates as $candidate) {
            $similarity = $this->compare($fingerprint, $candidate);
            if ($similarity >= $threshold) {
                $similar[] = [
                    'fingerprint' => $candidate,
                    'similarity' => $similarity,
                ];
            }
        }

        // Sort by similarity descending
        usort($similar, fn($a, $b) => $b['similarity'] <=> $a['similarity']);

        return $similar;
    }
}

/**
 * Attack fingerprint data object.
 */
class AttackFingerprint
{
    public function __construct(
        public readonly string $hash,
        public readonly array $components,
        public readonly float $confidence,
        public readonly int $timestamp
    ) {}

    public function toArray(): array
    {
        return [
            'hash' => $this->hash,
            'components' => $this->components,
            'confidence' => $this->confidence,
            'timestamp' => $this->timestamp,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            hash: $data['hash'],
            components: $data['components'],
            confidence: $data['confidence'],
            timestamp: $data['timestamp']
        );
    }
}
