<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Observability;

use Illuminate\Support\Facades\Cache;

/**
 * Threat Heatmap.
 *
 * Visual threat mapping and analytics:
 * - Geographic threat distribution
 * - Endpoint vulnerability map
 * - Time-based threat patterns
 * - Attack vector visualization
 */
class ThreatHeatmap
{
    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'retention_hours' => 168, // 7 days
            'grid_resolution' => 100,
            'time_buckets' => 24,
        ], $config);
    }

    /**
     * Record threat location.
     */
    public function recordThreat(array $threat): void
    {
        // Geographic heatmap
        if (isset($threat['country'])) {
            $this->incrementGeoCell($threat['country'], $threat['severity'] ?? 'medium');
        }

        // Endpoint heatmap
        if (isset($threat['path'])) {
            $this->incrementEndpointCell($threat['path'], $threat['type'] ?? 'unknown');
        }

        // Time-based heatmap
        $this->incrementTimeCell($threat['type'] ?? 'unknown');

        // Attack vector heatmap
        if (isset($threat['vector'])) {
            $this->incrementVectorCell($threat['vector'], $threat['severity'] ?? 'medium');
        }

        // IP-based heatmap (anonymized)
        if (isset($threat['ip'])) {
            $this->incrementIpCell($threat['ip']);
        }
    }

    /**
     * Get geographic heatmap data.
     */
    public function getGeoHeatmap(): array
    {
        $data = Cache::get('heatmap:geo', []);

        $total = array_sum(array_column($data, 'count'));

        return [
            'type' => 'geographic',
            'data' => $data,
            'total' => $total,
            'top_countries' => $this->getTopItems($data, 10),
            'severity_distribution' => $this->getSeverityDistribution($data),
        ];
    }

    /**
     * Get endpoint heatmap data.
     */
    public function getEndpointHeatmap(): array
    {
        $data = Cache::get('heatmap:endpoints', []);

        return [
            'type' => 'endpoint',
            'data' => $data,
            'hotspots' => $this->identifyHotspots($data),
            'by_method' => $this->groupByMethod($data),
            'vulnerability_score' => $this->calculateVulnerabilityScores($data),
        ];
    }

    /**
     * Get time-based heatmap data.
     */
    public function getTimeHeatmap(int $hours = 24): array
    {
        $data = [];
        $now = time();

        for ($h = 0; $h < $hours; $h++) {
            $hour = date('H', $now - ($h * 3600));
            $day = date('D', $now - ($h * 3600));
            $key = "heatmap:time:{$day}:{$hour}";
            $data["{$day} {$hour}:00"] = Cache::get($key, []);
        }

        return [
            'type' => 'temporal',
            'data' => array_reverse($data, true),
            'peak_hours' => $this->findPeakHours($data),
            'patterns' => $this->detectTimePatterns($data),
        ];
    }

    /**
     * Get attack vector heatmap.
     */
    public function getVectorHeatmap(): array
    {
        $data = Cache::get('heatmap:vectors', []);

        return [
            'type' => 'attack_vector',
            'data' => $data,
            'primary_vectors' => $this->getTopItems($data, 5),
            'severity_matrix' => $this->buildSeverityMatrix($data),
            'trend' => $this->calculateVectorTrend($data),
        ];
    }

    /**
     * Get combined heatmap visualization data.
     */
    public function getCombinedHeatmap(): array
    {
        return [
            'geographic' => $this->getGeoHeatmap(),
            'endpoints' => $this->getEndpointHeatmap(),
            'temporal' => $this->getTimeHeatmap(),
            'vectors' => $this->getVectorHeatmap(),
            'summary' => $this->getHeatmapSummary(),
        ];
    }

    /**
     * Get heatmap as grid for visualization.
     */
    public function getGridData(string $type): array
    {
        $data = match ($type) {
            'geo' => Cache::get('heatmap:geo', []),
            'endpoints' => Cache::get('heatmap:endpoints', []),
            'vectors' => Cache::get('heatmap:vectors', []),
            default => [],
        };

        $grid = [];
        $maxValue = 0;

        foreach ($data as $key => $item) {
            $count = $item['count'] ?? 0;
            $maxValue = max($maxValue, $count);
        }

        foreach ($data as $key => $item) {
            $count = $item['count'] ?? 0;
            $intensity = $maxValue > 0 ? $count / $maxValue : 0;

            $grid[] = [
                'id' => $key,
                'value' => $count,
                'intensity' => $intensity,
                'color' => $this->getHeatColor($intensity),
                'metadata' => $item,
            ];
        }

        return [
            'grid' => $grid,
            'max_value' => $maxValue,
            'total_cells' => count($grid),
        ];
    }

    /**
     * Get heatmap summary.
     */
    public function getHeatmapSummary(): array
    {
        $geo = Cache::get('heatmap:geo', []);
        $endpoints = Cache::get('heatmap:endpoints', []);
        $vectors = Cache::get('heatmap:vectors', []);

        return [
            'total_threats' => $this->sumCounts($geo) + $this->sumCounts($endpoints),
            'affected_countries' => count($geo),
            'affected_endpoints' => count($endpoints),
            'attack_vectors' => count($vectors),
            'most_targeted_country' => $this->getTopItem($geo),
            'most_targeted_endpoint' => $this->getTopItem($endpoints),
            'primary_attack_vector' => $this->getTopItem($vectors),
        ];
    }

    /**
     * Export heatmap for external visualization.
     */
    public function export(string $format = 'json'): string
    {
        $data = $this->getCombinedHeatmap();

        return match ($format) {
            'json' => json_encode($data, JSON_PRETTY_PRINT),
            'csv' => $this->toCsv($data),
            default => json_encode($data),
        };
    }

    /**
     * Increment geographic cell.
     */
    private function incrementGeoCell(string $country, string $severity): void
    {
        $key = 'heatmap:geo';
        $data = Cache::get($key, []);

        if (!isset($data[$country])) {
            $data[$country] = ['count' => 0, 'severities' => []];
        }

        $data[$country]['count']++;
        $data[$country]['severities'][$severity] = ($data[$country]['severities'][$severity] ?? 0) + 1;
        $data[$country]['last_seen'] = time();

        Cache::put($key, $data, $this->config['retention_hours'] * 3600);
    }

    /**
     * Increment endpoint cell.
     */
    private function incrementEndpointCell(string $path, string $threatType): void
    {
        $key = 'heatmap:endpoints';
        $data = Cache::get($key, []);

        $normalizedPath = $this->normalizePath($path);

        if (!isset($data[$normalizedPath])) {
            $data[$normalizedPath] = ['count' => 0, 'types' => [], 'methods' => []];
        }

        $data[$normalizedPath]['count']++;
        $data[$normalizedPath]['types'][$threatType] = ($data[$normalizedPath]['types'][$threatType] ?? 0) + 1;
        $data[$normalizedPath]['last_seen'] = time();

        Cache::put($key, $data, $this->config['retention_hours'] * 3600);
    }

    /**
     * Increment time cell.
     */
    private function incrementTimeCell(string $threatType): void
    {
        $day = date('D');
        $hour = date('H');
        $key = "heatmap:time:{$day}:{$hour}";

        $data = Cache::get($key, ['total' => 0, 'types' => []]);
        $data['total']++;
        $data['types'][$threatType] = ($data['types'][$threatType] ?? 0) + 1;

        Cache::put($key, $data, $this->config['retention_hours'] * 3600);
    }

    /**
     * Increment vector cell.
     */
    private function incrementVectorCell(string $vector, string $severity): void
    {
        $key = 'heatmap:vectors';
        $data = Cache::get($key, []);

        if (!isset($data[$vector])) {
            $data[$vector] = ['count' => 0, 'severities' => []];
        }

        $data[$vector]['count']++;
        $data[$vector]['severities'][$severity] = ($data[$vector]['severities'][$severity] ?? 0) + 1;

        Cache::put($key, $data, $this->config['retention_hours'] * 3600);
    }

    /**
     * Increment IP cell (anonymized).
     */
    private function incrementIpCell(string $ip): void
    {
        // Anonymize to /16 subnet
        $parts = explode('.', $ip);
        if (count($parts) >= 2) {
            $subnet = "{$parts[0]}.{$parts[1]}.0.0/16";

            $key = 'heatmap:ip_subnets';
            $data = Cache::get($key, []);

            $data[$subnet] = ($data[$subnet] ?? 0) + 1;

            Cache::put($key, $data, $this->config['retention_hours'] * 3600);
        }
    }

    /**
     * Normalize path for grouping.
     */
    private function normalizePath(string $path): string
    {
        $path = preg_replace('/\/\d+/', '/:id', $path);
        $path = preg_replace('/\/[a-f0-9-]{36}/', '/:uuid', $path);
        return $path;
    }

    /**
     * Get top items.
     */
    private function getTopItems(array $data, int $limit): array
    {
        uasort($data, fn($a, $b) => ($b['count'] ?? 0) <=> ($a['count'] ?? 0));
        return array_slice($data, 0, $limit, true);
    }

    /**
     * Get top single item.
     */
    private function getTopItem(array $data): ?string
    {
        $top = $this->getTopItems($data, 1);
        return array_key_first($top);
    }

    /**
     * Sum counts.
     */
    private function sumCounts(array $data): int
    {
        return array_sum(array_column($data, 'count'));
    }

    /**
     * Get severity distribution.
     */
    private function getSeverityDistribution(array $data): array
    {
        $distribution = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];

        foreach ($data as $item) {
            foreach ($item['severities'] ?? [] as $severity => $count) {
                $distribution[$severity] = ($distribution[$severity] ?? 0) + $count;
            }
        }

        return $distribution;
    }

    /**
     * Identify hotspots.
     */
    private function identifyHotspots(array $data): array
    {
        $threshold = array_sum(array_column($data, 'count')) / max(count($data), 1) * 2;

        return array_filter($data, fn($item) => ($item['count'] ?? 0) > $threshold);
    }

    /**
     * Group by method.
     */
    private function groupByMethod(array $data): array
    {
        $byMethod = [];

        foreach ($data as $path => $item) {
            foreach ($item['methods'] ?? [] as $method => $count) {
                $byMethod[$method] = ($byMethod[$method] ?? 0) + $count;
            }
        }

        return $byMethod;
    }

    /**
     * Calculate vulnerability scores.
     */
    private function calculateVulnerabilityScores(array $data): array
    {
        $scores = [];

        foreach ($data as $path => $item) {
            $count = $item['count'] ?? 0;
            $typeCount = count($item['types'] ?? []);
            $scores[$path] = min(100, ($count * 0.5) + ($typeCount * 10));
        }

        arsort($scores);
        return array_slice($scores, 0, 10, true);
    }

    /**
     * Find peak hours.
     */
    private function findPeakHours(array $data): array
    {
        $hourlyTotals = [];

        foreach ($data as $key => $item) {
            $hour = substr($key, -5, 2);
            $hourlyTotals[$hour] = ($hourlyTotals[$hour] ?? 0) + ($item['total'] ?? 0);
        }

        arsort($hourlyTotals);
        return array_slice($hourlyTotals, 0, 5, true);
    }

    /**
     * Detect time patterns.
     */
    private function detectTimePatterns(array $data): array
    {
        $patterns = [];

        // Check for business hours pattern
        $businessHours = 0;
        $offHours = 0;

        foreach ($data as $key => $item) {
            $hour = (int) substr($key, -5, 2);
            $count = $item['total'] ?? 0;

            if ($hour >= 9 && $hour <= 17) {
                $businessHours += $count;
            } else {
                $offHours += $count;
            }
        }

        if ($businessHours > $offHours * 1.5) {
            $patterns[] = ['type' => 'business_hours', 'confidence' => 0.8];
        } elseif ($offHours > $businessHours * 1.5) {
            $patterns[] = ['type' => 'off_hours', 'confidence' => 0.8];
        }

        return $patterns;
    }

    /**
     * Build severity matrix.
     */
    private function buildSeverityMatrix(array $data): array
    {
        $matrix = [];

        foreach ($data as $vector => $item) {
            $matrix[$vector] = $item['severities'] ?? [];
        }

        return $matrix;
    }

    /**
     * Calculate vector trend.
     */
    private function calculateVectorTrend(array $data): array
    {
        // Simplified trend calculation
        $trend = [];

        foreach ($data as $vector => $item) {
            $trend[$vector] = 'stable';
        }

        return $trend;
    }

    /**
     * Get heat color based on intensity.
     */
    private function getHeatColor(float $intensity): string
    {
        if ($intensity >= 0.8) return '#ff0000';
        if ($intensity >= 0.6) return '#ff6600';
        if ($intensity >= 0.4) return '#ffcc00';
        if ($intensity >= 0.2) return '#99cc00';
        return '#00cc00';
    }

    /**
     * Convert to CSV.
     */
    private function toCsv(array $data): string
    {
        $csv = "type,key,count,severity\n";

        foreach ($data as $type => $section) {
            if (isset($section['data'])) {
                foreach ($section['data'] as $key => $item) {
                    $count = $item['count'] ?? 0;
                    $csv .= "{$type},{$key},{$count},\n";
                }
            }
        }

        return $csv;
    }
}
