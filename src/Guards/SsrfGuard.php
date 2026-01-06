<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Detects Server-Side Request Forgery (SSRF) attacks.
 *
 * Prevents requests to internal networks, cloud metadata endpoints,
 * and dangerous URL schemes.
 */
class SsrfGuard extends AbstractGuard
{
    protected array $quickPatterns = ['internal_ip', 'metadata_endpoints'];

    /**
     * Blocked IP ranges (private networks).
     */
    protected array $blockedRanges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '0.0.0.0/8',
        '::1/128',
        'fc00::/7',
        'fe80::/10',
    ];

    /**
     * Cloud metadata endpoints.
     */
    protected array $metadataEndpoints = [
        '169.254.169.254',      // AWS, GCP, Azure
        '169.254.170.2',        // AWS ECS
        'metadata.google.internal',
        'metadata.goog',
        '100.100.100.200',      // Alibaba Cloud
        'instance-data',
    ];

    /**
     * Dangerous URL schemes.
     */
    protected array $blockedSchemes = [
        'file',
        'gopher',
        'dict',
        'ftp',
        'sftp',
        'ldap',
        'tftp',
        'jar',
    ];

    public function getName(): string
    {
        return 'ssrf';
    }

    protected function onBoot(): void
    {
        $this->blockedRanges = array_merge(
            $this->blockedRanges,
            $this->getConfig('blocked_ranges', [])
        );
        $this->metadataEndpoints = array_merge(
            $this->metadataEndpoints,
            $this->getConfig('metadata_endpoints', [])
        );
        $this->blockedSchemes = array_merge(
            $this->blockedSchemes,
            $this->getConfig('blocked_schemes', [])
        );
    }

    protected function getPatterns(): array
    {
        return [
            'internal_ip' => [
                '127\.\d+\.\d+\.\d+',
                '10\.\d+\.\d+\.\d+',
                '172\.(1[6-9]|2\d|3[01])\.\d+\.\d+',
                '192\.168\.\d+\.\d+',
                '169\.254\.\d+\.\d+',
                '0\.0\.0\.0',
                'localhost',
                '::1',
                '\[::1\]',
            ],
            'metadata_endpoints' => [
                '169\.254\.169\.254',
                '169\.254\.170\.2',
                'metadata\.google\.internal',
                'metadata\.goog',
                '100\.100\.100\.200',
                'instance-data',
            ],
            'dangerous_schemes' => [
                '^file://',
                '^gopher://',
                '^dict://',
                '^ftp://',
                '^sftp://',
                '^ldap://',
                '^tftp://',
            ],
            'dns_rebinding' => [
                '0x[0-9a-f]+\.[0-9a-f]+',
                '\d+\.\d+\.\d+\.\d+\.xip\.io',
                '\.nip\.io',
                '\.sslip\.io',
            ],
            'url_encoding_bypass' => [
                '%2f%2f',           // //
                '%00',              // null byte
                '@.*@',             // double @ bypass
                '#.*#',             // fragment bypass
            ],
        ];
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        $urls = $this->extractUrls($input);

        if (empty($urls)) {
            return $this->pass();
        }

        foreach ($urls as $url) {
            $result = $this->inspectUrl($url);
            if ($result !== null) {
                return $result;
            }
        }

        return $this->pass();
    }

    /**
     * Extract URLs from input.
     */
    protected function extractUrls(mixed $input): array
    {
        $urls = [];

        if (is_string($input)) {
            // Check if entire input is a URL
            if ($this->looksLikeUrl($input)) {
                $urls[] = $input;
            }
            // Extract embedded URLs
            preg_match_all(
                '/https?:\/\/[^\s<>"\']+|[a-z]+:\/\/[^\s<>"\']+/i',
                $input,
                $matches
            );
            $urls = array_merge($urls, $matches[0] ?? []);
        } elseif (is_array($input)) {
            foreach ($input as $key => $value) {
                // Check common URL field names
                if (in_array(strtolower((string) $key), ['url', 'uri', 'href', 'src', 'link', 'redirect', 'callback', 'return_url', 'next', 'target'])) {
                    if (is_string($value)) {
                        $urls[] = $value;
                    }
                }
                // Recurse into arrays
                if (is_array($value)) {
                    $urls = array_merge($urls, $this->extractUrls($value));
                } elseif (is_string($value) && $this->looksLikeUrl($value)) {
                    $urls[] = $value;
                }
            }
        }

        return array_unique($urls);
    }

    /**
     * Check if string looks like a URL.
     */
    protected function looksLikeUrl(string $value): bool
    {
        return (bool) preg_match('/^[a-z][a-z0-9+.-]*:\/\//i', $value);
    }

    /**
     * Inspect a single URL for SSRF indicators.
     */
    protected function inspectUrl(string $url): ?GuardResultInterface
    {
        $decoded = $this->decodeUrl($url);

        // Check for dangerous schemes
        if ($this->hasDangerousScheme($decoded)) {
            return $this->threat(
                'Dangerous URL scheme detected',
                ThreatLevel::CRITICAL,
                ['url' => substr($url, 0, 200), 'type' => 'dangerous_scheme']
            );
        }

        // Parse URL
        $parsed = parse_url($decoded);
        if ($parsed === false) {
            return null;
        }

        $host = $parsed['host'] ?? '';

        // Check for metadata endpoints
        if ($this->isMetadataEndpoint($host)) {
            return $this->threat(
                'Cloud metadata endpoint access attempt',
                ThreatLevel::CRITICAL,
                ['url' => substr($url, 0, 200), 'host' => $host, 'type' => 'metadata']
            );
        }

        // Resolve and check IP
        $ip = $this->resolveHost($host);
        if ($ip && $this->isBlockedIp($ip)) {
            return $this->threat(
                'Internal network access attempt (SSRF)',
                ThreatLevel::CRITICAL,
                ['url' => substr($url, 0, 200), 'host' => $host, 'resolved_ip' => $ip, 'type' => 'internal_ip']
            );
        }

        // Check for DNS rebinding patterns
        if ($this->isDnsRebindingAttempt($host)) {
            return $this->threat(
                'Potential DNS rebinding attack',
                ThreatLevel::HIGH,
                ['url' => substr($url, 0, 200), 'host' => $host, 'type' => 'dns_rebinding']
            );
        }

        // Check for URL encoding bypasses
        if ($this->hasEncodingBypass($url)) {
            return $this->threat(
                'URL encoding bypass attempt',
                ThreatLevel::HIGH,
                ['url' => substr($url, 0, 200), 'type' => 'encoding_bypass']
            );
        }

        return null;
    }

    /**
     * Decode URL (multiple passes for double encoding).
     */
    protected function decodeUrl(string $url): string
    {
        $decoded = $url;
        for ($i = 0; $i < 3; $i++) {
            $new = urldecode($decoded);
            if ($new === $decoded) {
                break;
            }
            $decoded = $new;
        }
        return $decoded;
    }

    /**
     * Check for dangerous URL schemes.
     */
    protected function hasDangerousScheme(string $url): bool
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        if ($scheme === null || $scheme === false) {
            return false;
        }
        return in_array(strtolower($scheme), $this->blockedSchemes, true);
    }

    /**
     * Check if host is a metadata endpoint.
     */
    protected function isMetadataEndpoint(string $host): bool
    {
        $host = strtolower($host);
        foreach ($this->metadataEndpoints as $endpoint) {
            if ($host === strtolower($endpoint) || str_ends_with($host, '.' . strtolower($endpoint))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolve hostname to IP (with caching).
     */
    protected function resolveHost(string $host): ?string
    {
        // Direct IP
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $host;
        }

        // Skip resolution for common safe domains (optional optimization)
        if ($this->getConfig('skip_resolution_for_public', false)) {
            return null;
        }

        // DNS resolution (cached by PHP)
        $ip = gethostbyname($host);
        return ($ip !== $host) ? $ip : null;
    }

    /**
     * Check if IP is in blocked ranges.
     */
    protected function isBlockedIp(string $ip): bool
    {
        if (!$this->getConfig('allow_private_networks', false)) {
            // Check private ranges
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return true;
            }
        }

        // Localhost variations
        if ($ip === '127.0.0.1' || $ip === '::1' || str_starts_with($ip, '127.')) {
            return true;
        }

        // 0.0.0.0
        if ($ip === '0.0.0.0') {
            return true;
        }

        return false;
    }

    /**
     * Check for DNS rebinding patterns.
     */
    protected function isDnsRebindingAttempt(string $host): bool
    {
        $rebindingDomains = ['.xip.io', '.nip.io', '.sslip.io', '.localtest.me'];
        $host = strtolower($host);

        foreach ($rebindingDomains as $domain) {
            if (str_ends_with($host, $domain)) {
                return true;
            }
        }

        // Hex-encoded IP patterns
        if (preg_match('/^0x[0-9a-f]+$/i', $host)) {
            return true;
        }

        return false;
    }

    /**
     * Check for URL encoding bypass attempts.
     */
    protected function hasEncodingBypass(string $url): bool
    {
        // Double @ sign (authentication bypass)
        if (substr_count($url, '@') > 1) {
            return true;
        }

        // Null bytes
        if (str_contains($url, '%00') || str_contains($url, "\0")) {
            return true;
        }

        // Multiple slashes after scheme
        if (preg_match('/^[a-z]+:\/{3,}/i', $url)) {
            return true;
        }

        return false;
    }
}
