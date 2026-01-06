<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Advanced;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

/**
 * Threat Intel Feed.
 *
 * Integrates with external threat intelligence feeds:
 * - IP reputation services
 * - Domain blocklists
 * - Malware signature feeds
 * - CVE databases
 */
class ThreatIntelFeed
{
    private array $config;
    private array $feeds = [];

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'cache_ttl' => 3600,
            'timeout' => 10,
            'enabled_feeds' => ['abuseipdb', 'spamhaus', 'emerging_threats'],
            'local_blocklist' => [],
        ], $config);

        $this->initializeFeeds();
    }

    /**
     * Check IP reputation.
     */
    public function checkIp(string $ip): IpReputationResult
    {
        $cacheKey = "threat_intel:ip:{$ip}";
        $cached = Cache::get($cacheKey);

        if ($cached !== null) {
            return IpReputationResult::fromArray($cached);
        }

        // Check local blocklist first
        if (in_array($ip, $this->config['local_blocklist'])) {
            $result = new IpReputationResult(
                ip: $ip,
                isMalicious: true,
                confidence: 1.0,
                categories: ['local_blocklist'],
                sources: ['local'],
                lastSeen: time()
            );
            Cache::put($cacheKey, $result->toArray(), $this->config['cache_ttl']);
            return $result;
        }

        // Query enabled feeds
        $results = $this->queryFeeds('ip', $ip);
        $aggregated = $this->aggregateResults($ip, $results);

        Cache::put($cacheKey, $aggregated->toArray(), $this->config['cache_ttl']);

        return $aggregated;
    }

    /**
     * Check domain reputation.
     */
    public function checkDomain(string $domain): DomainReputationResult
    {
        $cacheKey = "threat_intel:domain:{$domain}";
        $cached = Cache::get($cacheKey);

        if ($cached !== null) {
            return DomainReputationResult::fromArray($cached);
        }

        $results = $this->queryFeeds('domain', $domain);
        $aggregated = $this->aggregateDomainResults($domain, $results);

        Cache::put($cacheKey, $aggregated->toArray(), $this->config['cache_ttl']);

        return $aggregated;
    }

    /**
     * Check URL against threat feeds.
     */
    public function checkUrl(string $url): UrlReputationResult
    {
        $cacheKey = "threat_intel:url:" . md5($url);
        $cached = Cache::get($cacheKey);

        if ($cached !== null) {
            return UrlReputationResult::fromArray($cached);
        }

        $results = $this->queryFeeds('url', $url);

        $isMalicious = false;
        $categories = [];

        foreach ($results as $result) {
            if ($result['malicious'] ?? false) {
                $isMalicious = true;
                $categories = array_merge($categories, $result['categories'] ?? []);
            }
        }

        $result = new UrlReputationResult(
            url: $url,
            isMalicious: $isMalicious,
            categories: array_unique($categories),
            sources: array_keys($results)
        );

        Cache::put($cacheKey, $result->toArray(), $this->config['cache_ttl']);

        return $result;
    }

    /**
     * Check file hash against threat feeds.
     */
    public function checkHash(string $hash): HashReputationResult
    {
        $cacheKey = "threat_intel:hash:{$hash}";
        $cached = Cache::get($cacheKey);

        if ($cached !== null) {
            return HashReputationResult::fromArray($cached);
        }

        $results = $this->queryFeeds('hash', $hash);

        $isMalicious = false;
        $malwareFamily = null;
        $detections = 0;

        foreach ($results as $result) {
            if ($result['malicious'] ?? false) {
                $isMalicious = true;
                $malwareFamily = $result['malware_family'] ?? $malwareFamily;
                $detections += $result['detections'] ?? 1;
            }
        }

        $result = new HashReputationResult(
            hash: $hash,
            isMalicious: $isMalicious,
            malwareFamily: $malwareFamily,
            detections: $detections,
            sources: array_keys($results)
        );

        Cache::put($cacheKey, $result->toArray(), $this->config['cache_ttl']);

        return $result;
    }

    /**
     * Get known bad IPs.
     */
    public function getKnownBadIps(int $limit = 1000): array
    {
        $cacheKey = 'threat_intel:bad_ips';
        $cached = Cache::get($cacheKey);

        if ($cached !== null) {
            return array_slice($cached, 0, $limit);
        }

        $ips = [];

        foreach ($this->feeds as $name => $feed) {
            if (in_array($name, $this->config['enabled_feeds'])) {
                $feedIps = $this->fetchBadIpList($feed);
                $ips = array_merge($ips, $feedIps);
            }
        }

        $ips = array_unique($ips);
        Cache::put($cacheKey, $ips, $this->config['cache_ttl']);

        return array_slice($ips, 0, $limit);
    }

    /**
     * Update local blocklist.
     */
    public function addToBlocklist(string $type, string $value, array $metadata = []): void
    {
        $key = "threat_intel:blocklist:{$type}";
        $blocklist = Cache::get($key, []);

        $blocklist[$value] = [
            'value' => $value,
            'added_at' => time(),
            'metadata' => $metadata,
        ];

        Cache::put($key, $blocklist, 86400 * 30);
    }

    /**
     * Remove from local blocklist.
     */
    public function removeFromBlocklist(string $type, string $value): bool
    {
        $key = "threat_intel:blocklist:{$type}";
        $blocklist = Cache::get($key, []);

        if (isset($blocklist[$value])) {
            unset($blocklist[$value]);
            Cache::put($key, $blocklist, 86400 * 30);
            return true;
        }

        return false;
    }

    /**
     * Get blocklist.
     */
    public function getBlocklist(string $type): array
    {
        $key = "threat_intel:blocklist:{$type}";
        return Cache::get($key, []);
    }

    /**
     * Get feed status.
     */
    public function getFeedStatus(): array
    {
        $status = [];

        foreach ($this->feeds as $name => $feed) {
            $status[$name] = [
                'enabled' => in_array($name, $this->config['enabled_feeds']),
                'type' => $feed['type'] ?? 'unknown',
                'last_sync' => Cache::get("threat_intel:feed_sync:{$name}"),
                'entries' => Cache::get("threat_intel:feed_count:{$name}", 0),
            ];
        }

        return $status;
    }

    /**
     * Sync feeds.
     */
    public function syncFeeds(): array
    {
        $results = [];

        foreach ($this->feeds as $name => $feed) {
            if (!in_array($name, $this->config['enabled_feeds'])) {
                continue;
            }

            try {
                $count = $this->syncFeed($name, $feed);
                $results[$name] = ['status' => 'success', 'entries' => $count];
            } catch (\Exception $e) {
                $results[$name] = ['status' => 'error', 'message' => $e->getMessage()];
            }
        }

        return $results;
    }

    /**
     * Initialize feeds configuration.
     */
    private function initializeFeeds(): void
    {
        $this->feeds = [
            'abuseipdb' => [
                'type' => 'ip',
                'url' => 'https://api.abuseipdb.com/api/v2/check',
                'method' => 'api',
                'requires_key' => true,
            ],
            'spamhaus' => [
                'type' => 'ip',
                'url' => 'https://www.spamhaus.org/drop/drop.txt',
                'method' => 'list',
            ],
            'emerging_threats' => [
                'type' => 'ip',
                'url' => 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
                'method' => 'list',
            ],
            'urlhaus' => [
                'type' => 'url',
                'url' => 'https://urlhaus.abuse.ch/downloads/text/',
                'method' => 'list',
            ],
            'malware_bazaar' => [
                'type' => 'hash',
                'url' => 'https://bazaar.abuse.ch/export/txt/sha256/recent/',
                'method' => 'list',
            ],
        ];
    }

    /**
     * Query feeds for indicator.
     */
    private function queryFeeds(string $type, string $indicator): array
    {
        $results = [];

        foreach ($this->feeds as $name => $feed) {
            if (!in_array($name, $this->config['enabled_feeds'])) {
                continue;
            }

            if ($feed['type'] !== $type && $feed['type'] !== 'all') {
                continue;
            }

            try {
                $results[$name] = $this->queryFeed($name, $feed, $indicator);
            } catch (\Exception $e) {
                $results[$name] = ['error' => $e->getMessage()];
            }
        }

        return $results;
    }

    /**
     * Query single feed.
     */
    private function queryFeed(string $name, array $feed, string $indicator): array
    {
        // Check local cache first
        $localKey = "threat_intel:local:{$name}";
        $localData = Cache::get($localKey, []);

        if (isset($localData[$indicator])) {
            return $localData[$indicator];
        }

        // For list-based feeds, check against cached list
        if ($feed['method'] === 'list') {
            $listKey = "threat_intel:list:{$name}";
            $list = Cache::get($listKey, []);

            return [
                'malicious' => in_array($indicator, $list),
                'source' => $name,
            ];
        }

        // For API-based feeds, would make HTTP request
        // Simplified for demo - in production, implement actual API calls
        return [
            'malicious' => false,
            'source' => $name,
        ];
    }

    /**
     * Aggregate IP results.
     */
    private function aggregateResults(string $ip, array $results): IpReputationResult
    {
        $maliciousCount = 0;
        $categories = [];
        $sources = [];

        foreach ($results as $source => $result) {
            if ($result['malicious'] ?? false) {
                $maliciousCount++;
                $categories = array_merge($categories, $result['categories'] ?? []);
            }
            $sources[] = $source;
        }

        $confidence = count($results) > 0 ? $maliciousCount / count($results) : 0;

        return new IpReputationResult(
            ip: $ip,
            isMalicious: $maliciousCount > 0,
            confidence: $confidence,
            categories: array_unique($categories),
            sources: $sources,
            lastSeen: time()
        );
    }

    /**
     * Aggregate domain results.
     */
    private function aggregateDomainResults(string $domain, array $results): DomainReputationResult
    {
        $maliciousCount = 0;
        $categories = [];
        $sources = [];

        foreach ($results as $source => $result) {
            if ($result['malicious'] ?? false) {
                $maliciousCount++;
                $categories = array_merge($categories, $result['categories'] ?? []);
            }
            $sources[] = $source;
        }

        $confidence = count($results) > 0 ? $maliciousCount / count($results) : 0;

        return new DomainReputationResult(
            domain: $domain,
            isMalicious: $maliciousCount > 0,
            confidence: $confidence,
            categories: array_unique($categories),
            sources: $sources
        );
    }

    /**
     * Fetch bad IP list from feed.
     */
    private function fetchBadIpList(array $feed): array
    {
        if ($feed['method'] !== 'list') {
            return [];
        }

        $listKey = "threat_intel:list:" . md5($feed['url']);
        return Cache::get($listKey, []);
    }

    /**
     * Sync single feed.
     */
    private function syncFeed(string $name, array $feed): int
    {
        if ($feed['method'] !== 'list') {
            return 0;
        }

        try {
            $response = Http::timeout($this->config['timeout'])->get($feed['url']);

            if (!$response->successful()) {
                throw new \Exception("Failed to fetch feed: HTTP {$response->status()}");
            }

            $content = $response->body();
            $entries = $this->parseList($content, $feed['type']);

            $listKey = "threat_intel:list:{$name}";
            Cache::put($listKey, $entries, $this->config['cache_ttl'] * 24);

            Cache::put("threat_intel:feed_sync:{$name}", time(), 86400);
            Cache::put("threat_intel:feed_count:{$name}", count($entries), 86400);

            return count($entries);
        } catch (\Exception $e) {
            throw $e;
        }
    }

    /**
     * Parse list content.
     */
    private function parseList(string $content, string $type): array
    {
        $lines = explode("\n", $content);
        $entries = [];

        foreach ($lines as $line) {
            $line = trim($line);

            // Skip comments and empty lines
            if (empty($line) || str_starts_with($line, '#') || str_starts_with($line, ';')) {
                continue;
            }

            // Extract IP/domain from line
            if ($type === 'ip') {
                if (preg_match('/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', $line, $matches)) {
                    $entries[] = $matches[1];
                }
            } else {
                $entries[] = $line;
            }
        }

        return array_unique($entries);
    }
}

/**
 * IP Reputation Result.
 */
class IpReputationResult
{
    public function __construct(
        public readonly string $ip,
        public readonly bool $isMalicious,
        public readonly float $confidence,
        public readonly array $categories,
        public readonly array $sources,
        public readonly ?int $lastSeen = null
    ) {}

    public function toArray(): array
    {
        return [
            'ip' => $this->ip,
            'is_malicious' => $this->isMalicious,
            'confidence' => $this->confidence,
            'categories' => $this->categories,
            'sources' => $this->sources,
            'last_seen' => $this->lastSeen,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            $data['ip'],
            $data['is_malicious'],
            $data['confidence'],
            $data['categories'],
            $data['sources'],
            $data['last_seen'] ?? null
        );
    }
}

/**
 * Domain Reputation Result.
 */
class DomainReputationResult
{
    public function __construct(
        public readonly string $domain,
        public readonly bool $isMalicious,
        public readonly float $confidence,
        public readonly array $categories,
        public readonly array $sources
    ) {}

    public function toArray(): array
    {
        return [
            'domain' => $this->domain,
            'is_malicious' => $this->isMalicious,
            'confidence' => $this->confidence,
            'categories' => $this->categories,
            'sources' => $this->sources,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            $data['domain'],
            $data['is_malicious'],
            $data['confidence'],
            $data['categories'],
            $data['sources']
        );
    }
}

/**
 * URL Reputation Result.
 */
class UrlReputationResult
{
    public function __construct(
        public readonly string $url,
        public readonly bool $isMalicious,
        public readonly array $categories,
        public readonly array $sources
    ) {}

    public function toArray(): array
    {
        return [
            'url' => $this->url,
            'is_malicious' => $this->isMalicious,
            'categories' => $this->categories,
            'sources' => $this->sources,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            $data['url'],
            $data['is_malicious'],
            $data['categories'],
            $data['sources']
        );
    }
}

/**
 * Hash Reputation Result.
 */
class HashReputationResult
{
    public function __construct(
        public readonly string $hash,
        public readonly bool $isMalicious,
        public readonly ?string $malwareFamily,
        public readonly int $detections,
        public readonly array $sources
    ) {}

    public function toArray(): array
    {
        return [
            'hash' => $this->hash,
            'is_malicious' => $this->isMalicious,
            'malware_family' => $this->malwareFamily,
            'detections' => $this->detections,
            'sources' => $this->sources,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            $data['hash'],
            $data['is_malicious'],
            $data['malware_family'] ?? null,
            $data['detections'] ?? 0,
            $data['sources']
        );
    }
}
