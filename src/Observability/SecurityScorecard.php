<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Observability;

use Illuminate\Support\Facades\Cache;

/**
 * Security Scorecard.
 *
 * Calculates and tracks security posture scores:
 * - Overall security score
 * - Category-specific scores
 * - Trend analysis
 * - Recommendations
 */
class SecurityScorecard
{
    private array $config;
    private array $weights;

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'cache_ttl' => 300,
            'history_days' => 30,
        ], $config);

        $this->weights = [
            'threat_detection' => 0.25,
            'guard_coverage' => 0.20,
            'response_time' => 0.15,
            'false_positive_rate' => 0.15,
            'configuration' => 0.15,
            'compliance' => 0.10,
        ];
    }

    /**
     * Calculate overall security score.
     */
    public function calculate(): ScorecardResult
    {
        $categories = $this->calculateCategoryScores();

        $overallScore = 0;
        foreach ($categories as $category => $data) {
            $weight = $this->weights[$category] ?? 0;
            $overallScore += $data['score'] * $weight;
        }

        $grade = $this->scoreToGrade($overallScore);
        $trend = $this->calculateTrend();
        $recommendations = $this->generateRecommendations($categories);

        // Store for history
        $this->storeScore($overallScore, $categories);

        return new ScorecardResult(
            overallScore: round($overallScore, 1),
            grade: $grade,
            categories: $categories,
            trend: $trend,
            recommendations: $recommendations,
            timestamp: time()
        );
    }

    /**
     * Get score history.
     */
    public function getHistory(int $days = 7): array
    {
        $history = [];

        for ($i = $days - 1; $i >= 0; $i--) {
            $date = date('Y-m-d', strtotime("-{$i} days"));
            $key = "scorecard:history:{$date}";
            $data = Cache::get($key);

            if ($data !== null) {
                $history[$date] = $data;
            }
        }

        return $history;
    }

    /**
     * Get category breakdown.
     */
    public function getCategoryDetails(string $category): array
    {
        return match ($category) {
            'threat_detection' => $this->getThreatDetectionDetails(),
            'guard_coverage' => $this->getGuardCoverageDetails(),
            'response_time' => $this->getResponseTimeDetails(),
            'false_positive_rate' => $this->getFalsePositiveDetails(),
            'configuration' => $this->getConfigurationDetails(),
            'compliance' => $this->getComplianceDetails(),
            default => [],
        };
    }

    /**
     * Compare with benchmark.
     */
    public function compareBenchmark(): array
    {
        $current = $this->calculate();

        // Industry benchmarks (simplified)
        $benchmarks = [
            'industry_average' => 65,
            'top_quartile' => 85,
            'median' => 70,
        ];

        return [
            'current_score' => $current->overallScore,
            'benchmarks' => $benchmarks,
            'percentile' => $this->calculatePercentile($current->overallScore),
            'comparison' => [
                'vs_average' => $current->overallScore - $benchmarks['industry_average'],
                'vs_top' => $current->overallScore - $benchmarks['top_quartile'],
            ],
        ];
    }

    /**
     * Calculate category scores.
     */
    private function calculateCategoryScores(): array
    {
        return [
            'threat_detection' => $this->calculateThreatDetectionScore(),
            'guard_coverage' => $this->calculateGuardCoverageScore(),
            'response_time' => $this->calculateResponseTimeScore(),
            'false_positive_rate' => $this->calculateFalsePositiveScore(),
            'configuration' => $this->calculateConfigurationScore(),
            'compliance' => $this->calculateComplianceScore(),
        ];
    }

    /**
     * Calculate threat detection score.
     */
    private function calculateThreatDetectionScore(): array
    {
        $metrics = Cache::get('scorecard:metrics:threats', [
            'detected' => 0,
            'blocked' => 0,
            'missed' => 0,
        ]);

        $total = $metrics['detected'] + $metrics['missed'];
        $detectionRate = $total > 0 ? ($metrics['detected'] / $total) * 100 : 100;
        $blockRate = $metrics['detected'] > 0 ? ($metrics['blocked'] / $metrics['detected']) * 100 : 100;

        $score = ($detectionRate * 0.6) + ($blockRate * 0.4);

        return [
            'score' => min(100, $score),
            'metrics' => [
                'detection_rate' => round($detectionRate, 1),
                'block_rate' => round($blockRate, 1),
                'total_threats' => $metrics['detected'],
            ],
            'status' => $this->getStatus($score),
        ];
    }

    /**
     * Calculate guard coverage score.
     */
    private function calculateGuardCoverageScore(): array
    {
        $config = Cache::get('scorecard:guard_config', [
            'total_guards' => 20,
            'enabled_guards' => 15,
            'critical_guards' => 10,
            'critical_enabled' => 10,
        ]);

        $coverageRate = $config['total_guards'] > 0
            ? ($config['enabled_guards'] / $config['total_guards']) * 100
            : 0;

        $criticalRate = $config['critical_guards'] > 0
            ? ($config['critical_enabled'] / $config['critical_guards']) * 100
            : 100;

        $score = ($coverageRate * 0.4) + ($criticalRate * 0.6);

        return [
            'score' => min(100, $score),
            'metrics' => [
                'total_guards' => $config['total_guards'],
                'enabled_guards' => $config['enabled_guards'],
                'coverage_percent' => round($coverageRate, 1),
                'critical_coverage' => round($criticalRate, 1),
            ],
            'status' => $this->getStatus($score),
        ];
    }

    /**
     * Calculate response time score.
     */
    private function calculateResponseTimeScore(): array
    {
        $metrics = Cache::get('scorecard:metrics:response', [
            'avg_ms' => 50,
            'p95_ms' => 100,
            'p99_ms' => 200,
        ]);

        // Target: <50ms avg, <100ms p95
        $avgScore = max(0, 100 - ($metrics['avg_ms'] / 50 * 50));
        $p95Score = max(0, 100 - ($metrics['p95_ms'] / 100 * 50));

        $score = ($avgScore * 0.6) + ($p95Score * 0.4);

        return [
            'score' => min(100, $score),
            'metrics' => [
                'avg_latency_ms' => $metrics['avg_ms'],
                'p95_latency_ms' => $metrics['p95_ms'],
                'p99_latency_ms' => $metrics['p99_ms'],
            ],
            'status' => $this->getStatus($score),
        ];
    }

    /**
     * Calculate false positive score.
     */
    private function calculateFalsePositiveScore(): array
    {
        $metrics = Cache::get('scorecard:metrics:fp', [
            'total_blocks' => 1000,
            'false_positives' => 10,
        ]);

        $fpRate = $metrics['total_blocks'] > 0
            ? ($metrics['false_positives'] / $metrics['total_blocks']) * 100
            : 0;

        // Lower FP rate = higher score
        $score = max(0, 100 - ($fpRate * 10));

        return [
            'score' => min(100, $score),
            'metrics' => [
                'false_positive_rate' => round($fpRate, 2),
                'total_blocks' => $metrics['total_blocks'],
                'false_positives' => $metrics['false_positives'],
            ],
            'status' => $this->getStatus($score),
        ];
    }

    /**
     * Calculate configuration score.
     */
    private function calculateConfigurationScore(): array
    {
        $checks = [
            'https_enforced' => Cache::get('config:https_enforced', true),
            'rate_limiting' => Cache::get('config:rate_limiting', true),
            'logging_enabled' => Cache::get('config:logging_enabled', true),
            'alerting_configured' => Cache::get('config:alerting', false),
            'backup_configured' => Cache::get('config:backup', false),
            'encryption_enabled' => Cache::get('config:encryption', true),
        ];

        $passed = array_sum(array_map(fn($v) => $v ? 1 : 0, $checks));
        $total = count($checks);

        $score = ($passed / $total) * 100;

        return [
            'score' => $score,
            'metrics' => [
                'checks_passed' => $passed,
                'total_checks' => $total,
                'details' => $checks,
            ],
            'status' => $this->getStatus($score),
        ];
    }

    /**
     * Calculate compliance score.
     */
    private function calculateComplianceScore(): array
    {
        $frameworks = Cache::get('scorecard:compliance', [
            'owasp_top10' => 80,
            'pci_dss' => 75,
            'gdpr' => 90,
        ]);

        $score = count($frameworks) > 0 ? array_sum($frameworks) / count($frameworks) : 0;

        return [
            'score' => $score,
            'metrics' => [
                'frameworks' => $frameworks,
            ],
            'status' => $this->getStatus($score),
        ];
    }

    /**
     * Calculate trend.
     */
    private function calculateTrend(): array
    {
        $history = $this->getHistory(7);

        if (count($history) < 2) {
            return ['direction' => 'stable', 'change' => 0];
        }

        $scores = array_column($history, 'overall_score');
        $recent = end($scores);
        $previous = $scores[count($scores) - 2] ?? $recent;

        $change = $recent - $previous;

        return [
            'direction' => $change > 1 ? 'improving' : ($change < -1 ? 'declining' : 'stable'),
            'change' => round($change, 1),
            'week_avg' => round(array_sum($scores) / count($scores), 1),
        ];
    }

    /**
     * Generate recommendations.
     */
    private function generateRecommendations(array $categories): array
    {
        $recommendations = [];

        foreach ($categories as $category => $data) {
            if ($data['score'] < 70) {
                $recommendations[] = $this->getRecommendation($category, $data);
            }
        }

        // Sort by priority
        usort($recommendations, fn($a, $b) => $b['priority'] <=> $a['priority']);

        return array_slice($recommendations, 0, 5);
    }

    /**
     * Get recommendation for category.
     */
    private function getRecommendation(string $category, array $data): array
    {
        $recommendations = [
            'threat_detection' => [
                'title' => 'Improve Threat Detection',
                'description' => 'Enable additional guards or tune detection thresholds',
                'priority' => 90,
            ],
            'guard_coverage' => [
                'title' => 'Increase Guard Coverage',
                'description' => 'Enable more security guards, especially critical ones',
                'priority' => 85,
            ],
            'response_time' => [
                'title' => 'Optimize Response Time',
                'description' => 'Consider async execution or guard fusion',
                'priority' => 70,
            ],
            'false_positive_rate' => [
                'title' => 'Reduce False Positives',
                'description' => 'Review and tune guard thresholds',
                'priority' => 75,
            ],
            'configuration' => [
                'title' => 'Improve Configuration',
                'description' => 'Enable recommended security settings',
                'priority' => 80,
            ],
            'compliance' => [
                'title' => 'Enhance Compliance',
                'description' => 'Address compliance gaps in detected frameworks',
                'priority' => 65,
            ],
        ];

        $rec = $recommendations[$category] ?? [
            'title' => 'Improve ' . ucfirst($category),
            'description' => 'Review and improve this category',
            'priority' => 50,
        ];

        $rec['category'] = $category;
        $rec['current_score'] = $data['score'];

        return $rec;
    }

    /**
     * Store score for history.
     */
    private function storeScore(float $score, array $categories): void
    {
        $date = date('Y-m-d');
        $key = "scorecard:history:{$date}";

        Cache::put($key, [
            'overall_score' => $score,
            'categories' => $categories,
            'timestamp' => time(),
        ], 86400 * $this->config['history_days']);
    }

    /**
     * Convert score to grade.
     */
    private function scoreToGrade(float $score): string
    {
        if ($score >= 90) return 'A';
        if ($score >= 80) return 'B';
        if ($score >= 70) return 'C';
        if ($score >= 60) return 'D';
        return 'F';
    }

    /**
     * Get status from score.
     */
    private function getStatus(float $score): string
    {
        if ($score >= 80) return 'good';
        if ($score >= 60) return 'fair';
        return 'poor';
    }

    /**
     * Calculate percentile.
     */
    private function calculatePercentile(float $score): int
    {
        // Simplified percentile estimation
        if ($score >= 90) return 95;
        if ($score >= 80) return 80;
        if ($score >= 70) return 60;
        if ($score >= 60) return 40;
        return 20;
    }

    /**
     * Get threat detection details.
     */
    private function getThreatDetectionDetails(): array
    {
        return Cache::get('scorecard:details:threat_detection', []);
    }

    /**
     * Get guard coverage details.
     */
    private function getGuardCoverageDetails(): array
    {
        return Cache::get('scorecard:details:guard_coverage', []);
    }

    /**
     * Get response time details.
     */
    private function getResponseTimeDetails(): array
    {
        return Cache::get('scorecard:details:response_time', []);
    }

    /**
     * Get false positive details.
     */
    private function getFalsePositiveDetails(): array
    {
        return Cache::get('scorecard:details:false_positive', []);
    }

    /**
     * Get configuration details.
     */
    private function getConfigurationDetails(): array
    {
        return Cache::get('scorecard:details:configuration', []);
    }

    /**
     * Get compliance details.
     */
    private function getComplianceDetails(): array
    {
        return Cache::get('scorecard:details:compliance', []);
    }
}

/**
 * Scorecard Result.
 */
class ScorecardResult
{
    public function __construct(
        public readonly float $overallScore,
        public readonly string $grade,
        public readonly array $categories,
        public readonly array $trend,
        public readonly array $recommendations,
        public readonly int $timestamp
    ) {}

    public function isHealthy(): bool
    {
        return $this->overallScore >= 70;
    }

    public function toArray(): array
    {
        return [
            'overall_score' => $this->overallScore,
            'grade' => $this->grade,
            'categories' => $this->categories,
            'trend' => $this->trend,
            'recommendations' => $this->recommendations,
            'timestamp' => $this->timestamp,
        ];
    }
}
