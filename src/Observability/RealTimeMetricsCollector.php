<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Observability;

use Illuminate\Support\Facades\Cache;

/**
 * Real-Time Metrics Collector.
 *
 * Collects and aggregates security metrics:
 * - Request metrics
 * - Threat metrics
 * - Performance metrics
 * - Guard metrics
 */
class RealTimeMetricsCollector
{
    private array $config;
    private array $buffer = [];
    private int $bufferSize = 0;

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'buffer_size' => 100,
            'flush_interval' => 10,
            'retention_hours' => 24,
            'aggregation_intervals' => [60, 300, 3600], // 1min, 5min, 1hr
            'enabled_metrics' => ['requests', 'threats', 'guards', 'latency'],
        ], $config);
    }

    /**
     * Record metric.
     */
    public function record(string $metric, float $value, array $tags = []): void
    {
        $dataPoint = [
            'metric' => $metric,
            'value' => $value,
            'tags' => $tags,
            'timestamp' => microtime(true),
        ];

        $this->buffer[] = $dataPoint;
        $this->bufferSize++;

        if ($this->bufferSize >= $this->config['buffer_size']) {
            $this->flush();
        }
    }

    /**
     * Increment counter metric.
     */
    public function increment(string $metric, array $tags = [], int $amount = 1): void
    {
        $key = $this->getCounterKey($metric, $tags);
        Cache::increment($key, $amount);

        // Also record for time-series
        $this->record($metric, $amount, $tags);
    }

    /**
     * Record gauge metric.
     */
    public function gauge(string $metric, float $value, array $tags = []): void
    {
        $key = $this->getGaugeKey($metric, $tags);
        Cache::put($key, $value, $this->config['retention_hours'] * 3600);

        $this->record($metric, $value, $tags);
    }

    /**
     * Record histogram metric.
     */
    public function histogram(string $metric, float $value, array $tags = []): void
    {
        $key = $this->getHistogramKey($metric, $tags);
        $data = Cache::get($key, ['values' => [], 'count' => 0, 'sum' => 0]);

        $data['values'][] = $value;
        $data['count']++;
        $data['sum'] += $value;

        // Keep only last 1000 values
        if (count($data['values']) > 1000) {
            array_shift($data['values']);
        }

        Cache::put($key, $data, $this->config['retention_hours'] * 3600);

        $this->record($metric, $value, $tags);
    }

    /**
     * Record timing metric.
     */
    public function timing(string $metric, float $milliseconds, array $tags = []): void
    {
        $this->histogram("{$metric}_ms", $milliseconds, $tags);
    }

    /**
     * Start timer.
     */
    public function startTimer(string $metric): TimerContext
    {
        return new TimerContext($this, $metric);
    }

    /**
     * Record request metrics.
     */
    public function recordRequest(array $data): void
    {
        $tags = [
            'method' => $data['method'] ?? 'unknown',
            'path' => $this->normalizePath($data['path'] ?? '/'),
            'status' => (string) ($data['status'] ?? 200),
        ];

        $this->increment('requests_total', $tags);
        
        if (isset($data['latency'])) {
            $this->timing('request_latency', $data['latency'], $tags);
        }

        if (isset($data['blocked']) && $data['blocked']) {
            $this->increment('requests_blocked', $tags);
        }
    }

    /**
     * Record threat metrics.
     */
    public function recordThreat(array $data): void
    {
        $tags = [
            'type' => $data['type'] ?? 'unknown',
            'severity' => $data['severity'] ?? 'medium',
            'guard' => $data['guard'] ?? 'unknown',
        ];

        $this->increment('threats_detected', $tags);

        if (isset($data['blocked']) && $data['blocked']) {
            $this->increment('threats_blocked', $tags);
        }
    }

    /**
     * Record guard metrics.
     */
    public function recordGuardExecution(string $guard, float $executionTime, bool $passed): void
    {
        $tags = ['guard' => $guard];

        $this->increment('guard_executions', $tags);
        $this->timing('guard_execution_time', $executionTime * 1000, $tags);

        if (!$passed) {
            $this->increment('guard_blocks', $tags);
        }
    }

    /**
     * Get metric value.
     */
    public function getMetric(string $metric, array $tags = []): ?float
    {
        $key = $this->getCounterKey($metric, $tags);
        return Cache::get($key);
    }

    /**
     * Get aggregated metrics.
     */
    public function getAggregatedMetrics(string $metric, int $interval = 300): array
    {
        $key = "metrics:aggregated:{$metric}:{$interval}";
        return Cache::get($key, []);
    }

    /**
     * Get histogram statistics.
     */
    public function getHistogramStats(string $metric, array $tags = []): array
    {
        $key = $this->getHistogramKey($metric, $tags);
        $data = Cache::get($key);

        if ($data === null || empty($data['values'])) {
            return [
                'count' => 0,
                'sum' => 0,
                'avg' => 0,
                'min' => 0,
                'max' => 0,
                'p50' => 0,
                'p90' => 0,
                'p99' => 0,
            ];
        }

        $values = $data['values'];
        sort($values);

        return [
            'count' => $data['count'],
            'sum' => $data['sum'],
            'avg' => $data['sum'] / $data['count'],
            'min' => min($values),
            'max' => max($values),
            'p50' => $this->percentile($values, 50),
            'p90' => $this->percentile($values, 90),
            'p99' => $this->percentile($values, 99),
        ];
    }

    /**
     * Get summary metrics.
     */
    public function getSummary(): array
    {
        return [
            'requests' => [
                'total' => Cache::get('metrics:counter:requests_total', 0),
                'blocked' => Cache::get('metrics:counter:requests_blocked', 0),
                'latency' => $this->getHistogramStats('request_latency_ms'),
            ],
            'threats' => [
                'detected' => Cache::get('metrics:counter:threats_detected', 0),
                'blocked' => Cache::get('metrics:counter:threats_blocked', 0),
                'by_type' => $this->getMetricsByTag('threats_detected', 'type'),
            ],
            'guards' => [
                'executions' => Cache::get('metrics:counter:guard_executions', 0),
                'blocks' => Cache::get('metrics:counter:guard_blocks', 0),
                'execution_time' => $this->getHistogramStats('guard_execution_time_ms'),
            ],
        ];
    }

    /**
     * Get time series data.
     */
    public function getTimeSeries(string $metric, int $duration = 3600, int $resolution = 60): array
    {
        $key = "metrics:timeseries:{$metric}";
        $data = Cache::get($key, []);

        $now = time();
        $start = $now - $duration;
        $series = [];

        for ($t = $start; $t <= $now; $t += $resolution) {
            $bucket = (int) ($t / $resolution) * $resolution;
            $series[$bucket] = $data[$bucket] ?? 0;
        }

        return $series;
    }

    /**
     * Flush buffer.
     */
    public function flush(): void
    {
        if (empty($this->buffer)) {
            return;
        }

        // Aggregate by minute
        $aggregated = [];
        foreach ($this->buffer as $point) {
            $bucket = (int) ($point['timestamp'] / 60) * 60;
            $key = $point['metric'] . ':' . $this->serializeTags($point['tags']);

            if (!isset($aggregated[$bucket][$key])) {
                $aggregated[$bucket][$key] = [
                    'metric' => $point['metric'],
                    'tags' => $point['tags'],
                    'sum' => 0,
                    'count' => 0,
                    'min' => PHP_FLOAT_MAX,
                    'max' => PHP_FLOAT_MIN,
                ];
            }

            $aggregated[$bucket][$key]['sum'] += $point['value'];
            $aggregated[$bucket][$key]['count']++;
            $aggregated[$bucket][$key]['min'] = min($aggregated[$bucket][$key]['min'], $point['value']);
            $aggregated[$bucket][$key]['max'] = max($aggregated[$bucket][$key]['max'], $point['value']);
        }

        // Store aggregated data
        foreach ($aggregated as $bucket => $metrics) {
            foreach ($metrics as $key => $data) {
                $cacheKey = "metrics:timeseries:{$data['metric']}";
                $existing = Cache::get($cacheKey, []);
                $existing[$bucket] = ($existing[$bucket] ?? 0) + $data['sum'];
                Cache::put($cacheKey, $existing, $this->config['retention_hours'] * 3600);
            }
        }

        $this->buffer = [];
        $this->bufferSize = 0;
    }

    /**
     * Get counter key.
     */
    private function getCounterKey(string $metric, array $tags): string
    {
        $tagStr = $this->serializeTags($tags);
        return "metrics:counter:{$metric}" . ($tagStr ? ":{$tagStr}" : '');
    }

    /**
     * Get gauge key.
     */
    private function getGaugeKey(string $metric, array $tags): string
    {
        $tagStr = $this->serializeTags($tags);
        return "metrics:gauge:{$metric}" . ($tagStr ? ":{$tagStr}" : '');
    }

    /**
     * Get histogram key.
     */
    private function getHistogramKey(string $metric, array $tags): string
    {
        $tagStr = $this->serializeTags($tags);
        return "metrics:histogram:{$metric}" . ($tagStr ? ":{$tagStr}" : '');
    }

    /**
     * Serialize tags.
     */
    private function serializeTags(array $tags): string
    {
        if (empty($tags)) {
            return '';
        }
        ksort($tags);
        return implode(',', array_map(fn($k, $v) => "{$k}={$v}", array_keys($tags), $tags));
    }

    /**
     * Calculate percentile.
     */
    private function percentile(array $values, int $percentile): float
    {
        $count = count($values);
        if ($count === 0) {
            return 0;
        }

        $index = ($percentile / 100) * ($count - 1);
        $lower = (int) floor($index);
        $upper = (int) ceil($index);
        $fraction = $index - $lower;

        if ($lower === $upper) {
            return $values[$lower];
        }

        return $values[$lower] * (1 - $fraction) + $values[$upper] * $fraction;
    }

    /**
     * Normalize path for metrics.
     */
    private function normalizePath(string $path): string
    {
        // Replace IDs with placeholders
        $path = preg_replace('/\/\d+/', '/:id', $path);
        $path = preg_replace('/\/[a-f0-9-]{36}/', '/:uuid', $path);
        return $path;
    }

    /**
     * Get metrics grouped by tag.
     */
    private function getMetricsByTag(string $metric, string $tagName): array
    {
        $pattern = "metrics:counter:{$metric}:*{$tagName}=*";
        // In production, use Cache::tags() or scan for pattern
        return Cache::get("metrics:by_tag:{$metric}:{$tagName}", []);
    }
}

/**
 * Timer Context.
 */
class TimerContext
{
    private RealTimeMetricsCollector $collector;
    private string $metric;
    private float $startTime;
    private array $tags = [];

    public function __construct(RealTimeMetricsCollector $collector, string $metric)
    {
        $this->collector = $collector;
        $this->metric = $metric;
        $this->startTime = microtime(true);
    }

    public function addTag(string $key, string $value): self
    {
        $this->tags[$key] = $value;
        return $this;
    }

    public function stop(): float
    {
        $duration = (microtime(true) - $this->startTime) * 1000;
        $this->collector->timing($this->metric, $duration, $this->tags);
        return $duration;
    }

    public function __destruct()
    {
        if ($this->startTime > 0) {
            $this->stop();
        }
    }
}
