<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Guards;

use Mounir\RuntimeGuard\Contracts\GuardInterface;
use Mounir\RuntimeGuard\Context\RuntimeContext;
use Mounir\RuntimeGuard\Results\GuardResult;

/**
 * Request Signature Validator Guard.
 *
 * Validates HMAC request signatures for API authentication:
 * - HMAC signature verification
 * - Timestamp freshness check
 * - Nonce validation (replay prevention)
 * - Multiple signature schemes support
 */
class RequestSignatureGuard implements GuardInterface
{
    private bool $enabled;
    private array $secrets;
    private string $signatureHeader;
    private string $timestampHeader;
    private string $nonceHeader;
    private int $timestampTolerance;
    private string $defaultAlgorithm;
    private bool $requireTimestamp;
    private bool $requireNonce;
    private ?object $cache;
    private int $nonceTtl;

    public function __construct(array $config = [])
    {
        $this->enabled = $config['enabled'] ?? true;
        $this->secrets = $config['secrets'] ?? [];
        $this->signatureHeader = $config['signature_header'] ?? 'X-Signature';
        $this->timestampHeader = $config['timestamp_header'] ?? 'X-Timestamp';
        $this->nonceHeader = $config['nonce_header'] ?? 'X-Nonce';
        $this->timestampTolerance = $config['timestamp_tolerance'] ?? 300; // 5 minutes
        $this->defaultAlgorithm = $config['default_algorithm'] ?? 'sha256';
        $this->requireTimestamp = $config['require_timestamp'] ?? true;
        $this->requireNonce = $config['require_nonce'] ?? false;
        $this->cache = $config['cache'] ?? null;
        $this->nonceTtl = $config['nonce_ttl'] ?? 3600;
    }

    public function inspect(RuntimeContext $context): GuardResult
    {
        if (!$this->enabled) {
            return GuardResult::pass($this->getName());
        }

        if (empty($this->secrets)) {
            return GuardResult::pass($this->getName())
                ->withMetadata(['skipped' => 'no_secrets_configured']);
        }

        $request = $context->getRequest();
        $threats = [];
        $metadata = [];

        // Get signature from request
        $signature = $this->extractSignature($request);

        if (!$signature) {
            // No signature provided - might be optional
            return GuardResult::pass($this->getName())
                ->withMetadata(['signature_present' => false]);
        }

        $metadata['signature_present'] = true;

        // Check 1: Timestamp validation
        if ($this->requireTimestamp) {
            $timestampResult = $this->validateTimestamp($request);
            if (!$timestampResult['valid']) {
                $threats[] = $timestampResult['threat'];
            }
            $metadata['timestamp_validation'] = $timestampResult;
        }

        // Check 2: Nonce validation (replay prevention)
        if ($this->requireNonce) {
            $nonceResult = $this->validateNonce($request);
            if (!$nonceResult['valid']) {
                $threats[] = $nonceResult['threat'];
            }
            $metadata['nonce_validation'] = $nonceResult;
        }

        // Check 3: Signature validation
        $signatureResult = $this->validateSignature($request, $signature);
        if (!$signatureResult['valid']) {
            $threats[] = $signatureResult['threat'];
        }
        $metadata['signature_validation'] = $signatureResult;

        if (!empty($threats)) {
            return GuardResult::fail($this->getName(), $threats)
                ->withMetadata($metadata);
        }

        return GuardResult::pass($this->getName())
            ->withMetadata($metadata);
    }

    /**
     * Extract signature from request.
     */
    private function extractSignature(object $request): ?array
    {
        $signatureHeader = $request->header($this->signatureHeader);

        if (!$signatureHeader) {
            return null;
        }

        // Parse signature header
        // Format: algorithm=value or t=timestamp,v1=signature
        $parsed = $this->parseSignatureHeader($signatureHeader);

        return $parsed;
    }

    /**
     * Parse signature header.
     */
    private function parseSignatureHeader(string $header): array
    {
        $result = [
            'algorithm' => $this->defaultAlgorithm,
            'signature' => null,
            'timestamp' => null,
            'version' => null,
        ];

        // Format 1: Simple base64 signature
        if (!str_contains($header, '=') || preg_match('/^[A-Za-z0-9+\/=]+$/', $header)) {
            $result['signature'] = $header;
            return $result;
        }

        // Format 2: Stripe-style (t=123,v1=abc)
        if (str_contains($header, ',')) {
            $parts = explode(',', $header);
            foreach ($parts as $part) {
                $part = trim($part);
                if (str_starts_with($part, 't=')) {
                    $result['timestamp'] = substr($part, 2);
                } elseif (preg_match('/^v(\d+)=(.+)$/', $part, $matches)) {
                    $result['version'] = $matches[1];
                    $result['signature'] = $matches[2];
                }
            }
            return $result;
        }

        // Format 3: Algorithm=signature
        if (str_contains($header, '=')) {
            [$algo, $sig] = explode('=', $header, 2);
            $result['algorithm'] = strtolower($algo);
            $result['signature'] = $sig;
        }

        return $result;
    }

    /**
     * Validate timestamp.
     */
    private function validateTimestamp(object $request): array
    {
        $timestamp = $request->header($this->timestampHeader);

        if (!$timestamp) {
            return [
                'valid' => false,
                'threat' => [
                    'type' => 'signature_missing_timestamp',
                    'severity' => 'high',
                    'message' => 'Request signature missing required timestamp',
                ],
            ];
        }

        // Parse timestamp (Unix timestamp or ISO 8601)
        if (is_numeric($timestamp)) {
            $time = (int) $timestamp;
        } else {
            $time = strtotime($timestamp);
        }

        if ($time === false) {
            return [
                'valid' => false,
                'threat' => [
                    'type' => 'signature_invalid_timestamp',
                    'severity' => 'high',
                    'message' => 'Request signature has invalid timestamp format',
                    'details' => ['timestamp' => $timestamp],
                ],
            ];
        }

        $now = time();
        $diff = abs($now - $time);

        if ($diff > $this->timestampTolerance) {
            $direction = $time < $now ? 'past' : 'future';
            return [
                'valid' => false,
                'threat' => [
                    'type' => 'signature_timestamp_expired',
                    'severity' => 'high',
                    'message' => "Request signature timestamp too far in the {$direction}",
                    'details' => [
                        'timestamp' => $time,
                        'diff_seconds' => $diff,
                        'tolerance' => $this->timestampTolerance,
                    ],
                ],
            ];
        }

        return [
            'valid' => true,
            'timestamp' => $time,
            'diff_seconds' => $diff,
        ];
    }

    /**
     * Validate nonce.
     */
    private function validateNonce(object $request): array
    {
        $nonce = $request->header($this->nonceHeader);

        if (!$nonce) {
            return [
                'valid' => false,
                'threat' => [
                    'type' => 'signature_missing_nonce',
                    'severity' => 'high',
                    'message' => 'Request signature missing required nonce',
                ],
            ];
        }

        // Check for nonce format (should be random, UUID-like, or timestamp-based)
        if (strlen($nonce) < 16) {
            return [
                'valid' => false,
                'threat' => [
                    'type' => 'signature_weak_nonce',
                    'severity' => 'medium',
                    'message' => 'Request nonce is too short',
                    'details' => ['nonce_length' => strlen($nonce)],
                ],
            ];
        }

        // Check for replay (if cache available)
        if ($this->cache) {
            $cacheKey = "sig_nonce:{$nonce}";

            if ($this->cache->has($cacheKey)) {
                return [
                    'valid' => false,
                    'threat' => [
                        'type' => 'signature_nonce_replay',
                        'severity' => 'critical',
                        'message' => 'Request nonce already used - replay attack detected',
                        'details' => ['nonce' => substr($nonce, 0, 16) . '...'],
                    ],
                ];
            }

            // Store nonce
            $this->cache->put($cacheKey, time(), $this->nonceTtl);
        }

        return [
            'valid' => true,
            'nonce' => $nonce,
        ];
    }

    /**
     * Validate signature.
     */
    private function validateSignature(object $request, array $signatureInfo): array
    {
        $signature = $signatureInfo['signature'];
        $algorithm = $signatureInfo['algorithm'];

        if (!$signature) {
            return [
                'valid' => false,
                'threat' => [
                    'type' => 'signature_missing',
                    'severity' => 'high',
                    'message' => 'Request signature is empty or malformed',
                ],
            ];
        }

        // Build the signing string
        $signingString = $this->buildSigningString($request, $signatureInfo);

        // Try each secret
        $validSecrets = [];
        foreach ($this->secrets as $keyId => $secret) {
            $expected = $this->computeSignature($signingString, $secret, $algorithm);

            // Timing-safe comparison
            if (hash_equals($expected, $signature)) {
                $validSecrets[] = $keyId;
            }
        }

        if (empty($validSecrets)) {
            return [
                'valid' => false,
                'threat' => [
                    'type' => 'signature_invalid',
                    'severity' => 'critical',
                    'message' => 'Request signature verification failed',
                    'details' => [
                        'algorithm' => $algorithm,
                    ],
                ],
            ];
        }

        return [
            'valid' => true,
            'matched_keys' => $validSecrets,
            'algorithm' => $algorithm,
        ];
    }

    /**
     * Build the string to sign.
     */
    private function buildSigningString(object $request, array $signatureInfo): string
    {
        $parts = [];

        // Include timestamp if present
        $timestamp = $signatureInfo['timestamp'] ?? $request->header($this->timestampHeader);
        if ($timestamp) {
            $parts[] = $timestamp;
        }

        // Include method
        $parts[] = $request->method();

        // Include path
        $parts[] = $request->path();

        // Include query string (sorted)
        $query = $request->query();
        if (!empty($query)) {
            ksort($query);
            $parts[] = http_build_query($query);
        }

        // Include body for POST/PUT/PATCH
        if (in_array($request->method(), ['POST', 'PUT', 'PATCH'])) {
            $body = $request->getContent();
            if ($body) {
                $parts[] = $body;
            }
        }

        return implode('.', $parts);
    }

    /**
     * Compute HMAC signature.
     */
    private function computeSignature(string $data, string $secret, string $algorithm): string
    {
        $algo = match (strtolower($algorithm)) {
            'sha256', 'hmac-sha256' => 'sha256',
            'sha384', 'hmac-sha384' => 'sha384',
            'sha512', 'hmac-sha512' => 'sha512',
            'sha1', 'hmac-sha1' => 'sha1',
            'md5', 'hmac-md5' => 'md5', // Not recommended
            default => 'sha256',
        };

        return hash_hmac($algo, $data, $secret);
    }

    /**
     * Generate a signature for a request.
     * Utility method for clients to generate signatures.
     */
    public function generateSignature(
        string $method,
        string $path,
        string $body,
        int $timestamp,
        string $secret,
        string $algorithm = 'sha256'
    ): string {
        $signingString = implode('.', [
            $timestamp,
            strtoupper($method),
            $path,
            $body,
        ]);

        return $this->computeSignature($signingString, $secret, $algorithm);
    }

    public function getName(): string
    {
        return 'request_signature';
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getPriority(): int
    {
        return 90; // Run early
    }

    public function getSeverity(): string
    {
        return 'high';
    }
}
