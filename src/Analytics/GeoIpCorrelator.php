<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Analytics;

use Illuminate\Support\Facades\Cache;

/**
 * Geo-IP Correlation.
 *
 * Correlates attacks with geographic data for threat intelligence.
 */
class GeoIpCorrelator
{
    protected ?object $reader = null;
    protected string $databasePath;
    protected bool $enabled;
    protected array $cache = [];

    public function __construct()
    {
        $this->databasePath = config('runtime-guard.analytics.geoip.database_path', storage_path('app/geoip/GeoLite2-City.mmdb'));
        $this->enabled = config('runtime-guard.analytics.geoip.enabled', false);
    }

    /**
     * Initialize the GeoIP reader.
     */
    protected function initReader(): bool
    {
        if ($this->reader !== null) {
            return true;
        }

        if (!file_exists($this->databasePath)) {
            return false;
        }

        // Check for MaxMind reader
        if (class_exists(\GeoIp2\Database\Reader::class)) {
            try {
                $this->reader = new \GeoIp2\Database\Reader($this->databasePath);
                return true;
            } catch (\Throwable $e) {
                return false;
            }
        }

        return false;
    }

    /**
     * Look up geographic data for an IP address.
     */
    public function lookup(string $ip): ?GeoIpResult
    {
        if (!$this->enabled) {
            return null;
        }

        // Check cache
        $cacheKey = "geoip:{$ip}";
        if (isset($this->cache[$ip])) {
            return $this->cache[$ip];
        }

        $cached = Cache::get($cacheKey);
        if ($cached !== null) {
            $result = GeoIpResult::fromArray($cached);
            $this->cache[$ip] = $result;
            return $result;
        }

        // Validate IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        // Skip private IPs
        if ($this->isPrivateIp($ip)) {
            return new GeoIpResult(
                ip: $ip,
                country: 'Private',
                countryCode: 'XX',
                city: null,
                region: null,
                latitude: null,
                longitude: null,
                timezone: null,
                isPrivate: true
            );
        }

        // Look up using MaxMind
        if ($this->initReader()) {
            $result = $this->lookupMaxMind($ip);
            if ($result) {
                Cache::put($cacheKey, $result->toArray(), 86400); // Cache for 24h
                $this->cache[$ip] = $result;
                return $result;
            }
        }

        // Fallback to IP-API (free tier)
        $result = $this->lookupIpApi($ip);
        if ($result) {
            Cache::put($cacheKey, $result->toArray(), 86400);
            $this->cache[$ip] = $result;
        }

        return $result;
    }

    /**
     * Look up using MaxMind database.
     */
    protected function lookupMaxMind(string $ip): ?GeoIpResult
    {
        try {
            $record = $this->reader->city($ip);

            return new GeoIpResult(
                ip: $ip,
                country: $record->country->name,
                countryCode: $record->country->isoCode,
                city: $record->city->name,
                region: $record->mostSpecificSubdivision->name,
                latitude: $record->location->latitude,
                longitude: $record->location->longitude,
                timezone: $record->location->timeZone,
                isPrivate: false,
                asn: null,
                org: null
            );
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Look up using IP-API (free fallback).
     */
    protected function lookupIpApi(string $ip): ?GeoIpResult
    {
        try {
            $response = @file_get_contents("http://ip-api.com/json/{$ip}?fields=status,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as");

            if (!$response) {
                return null;
            }

            $data = json_decode($response, true);

            if (($data['status'] ?? '') !== 'success') {
                return null;
            }

            return new GeoIpResult(
                ip: $ip,
                country: $data['country'] ?? null,
                countryCode: $data['countryCode'] ?? null,
                city: $data['city'] ?? null,
                region: $data['regionName'] ?? null,
                latitude: $data['lat'] ?? null,
                longitude: $data['lon'] ?? null,
                timezone: $data['timezone'] ?? null,
                isPrivate: false,
                asn: $data['as'] ?? null,
                org: $data['org'] ?? null
            );
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Check if IP is private.
     */
    protected function isPrivateIp(string $ip): bool
    {
        return !filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    /**
     * Correlate multiple IPs and find patterns.
     */
    public function correlate(array $ips): CorrelationResult
    {
        $results = [];
        $countries = [];
        $cities = [];
        $timezones = [];

        foreach ($ips as $ip) {
            $geo = $this->lookup($ip);
            if ($geo) {
                $results[$ip] = $geo;

                if ($geo->countryCode) {
                    $countries[$geo->countryCode] = ($countries[$geo->countryCode] ?? 0) + 1;
                }
                if ($geo->city) {
                    $cities[$geo->city] = ($cities[$geo->city] ?? 0) + 1;
                }
                if ($geo->timezone) {
                    $timezones[$geo->timezone] = ($timezones[$geo->timezone] ?? 0) + 1;
                }
            }
        }

        // Sort by frequency
        arsort($countries);
        arsort($cities);
        arsort($timezones);

        return new CorrelationResult(
            results: $results,
            topCountries: array_slice($countries, 0, 10, true),
            topCities: array_slice($cities, 0, 10, true),
            topTimezones: array_slice($timezones, 0, 5, true),
            totalIps: count($ips),
            resolvedIps: count($results)
        );
    }

    /**
     * Check if GeoIP is available.
     */
    public function isAvailable(): bool
    {
        return $this->enabled && ($this->initReader() || true); // IP-API fallback always available
    }

    /**
     * Get statistics.
     */
    public function getStatistics(): array
    {
        return [
            'enabled' => $this->enabled,
            'database_exists' => file_exists($this->databasePath),
            'maxmind_available' => class_exists(\GeoIp2\Database\Reader::class),
            'cache_size' => count($this->cache),
        ];
    }
}

/**
 * GeoIP lookup result.
 */
class GeoIpResult
{
    public function __construct(
        public readonly string $ip,
        public readonly ?string $country,
        public readonly ?string $countryCode,
        public readonly ?string $city,
        public readonly ?string $region,
        public readonly ?float $latitude,
        public readonly ?float $longitude,
        public readonly ?string $timezone,
        public readonly bool $isPrivate = false,
        public readonly ?string $asn = null,
        public readonly ?string $org = null
    ) {}

    public function toArray(): array
    {
        return [
            'ip' => $this->ip,
            'country' => $this->country,
            'country_code' => $this->countryCode,
            'city' => $this->city,
            'region' => $this->region,
            'latitude' => $this->latitude,
            'longitude' => $this->longitude,
            'timezone' => $this->timezone,
            'is_private' => $this->isPrivate,
            'asn' => $this->asn,
            'org' => $this->org,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            ip: $data['ip'],
            country: $data['country'],
            countryCode: $data['country_code'],
            city: $data['city'],
            region: $data['region'],
            latitude: $data['latitude'],
            longitude: $data['longitude'],
            timezone: $data['timezone'],
            isPrivate: $data['is_private'] ?? false,
            asn: $data['asn'] ?? null,
            org: $data['org'] ?? null
        );
    }
}

/**
 * Correlation result container.
 */
class CorrelationResult
{
    public function __construct(
        public readonly array $results,
        public readonly array $topCountries,
        public readonly array $topCities,
        public readonly array $topTimezones,
        public readonly int $totalIps,
        public readonly int $resolvedIps
    ) {}

    public function toArray(): array
    {
        return [
            'results' => array_map(fn($r) => $r->toArray(), $this->results),
            'top_countries' => $this->topCountries,
            'top_cities' => $this->topCities,
            'top_timezones' => $this->topTimezones,
            'total_ips' => $this->totalIps,
            'resolved_ips' => $this->resolvedIps,
            'resolution_rate' => $this->totalIps > 0 ? round($this->resolvedIps / $this->totalIps * 100, 2) : 0,
        ];
    }
}
