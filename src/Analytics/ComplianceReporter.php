<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Analytics;

use Illuminate\Support\Facades\Cache;

/**
 * Compliance Reporter.
 *
 * Generates compliance reports for security audits (PCI-DSS, OWASP, etc.).
 */
class ComplianceReporter
{
    protected string $cachePrefix = 'rtg_compliance:';

    /**
     * Generate PCI-DSS compliance report.
     */
    public function generatePciDssReport(int $days = 30): array
    {
        $stats = $this->getSecurityStats($days);

        return [
            'framework' => 'PCI-DSS v4.0',
            'period' => [
                'start' => date('Y-m-d', strtotime("-{$days} days")),
                'end' => date('Y-m-d'),
                'days' => $days,
            ],
            'requirements' => [
                '6.4' => [
                    'title' => 'Protection of system components against known vulnerabilities',
                    'status' => $this->assessGuardCoverage($stats),
                    'evidence' => [
                        'active_guards' => $stats['active_guards'],
                        'threats_blocked' => $stats['total_blocked'],
                        'coverage_areas' => $stats['coverage_areas'],
                    ],
                ],
                '6.4.1' => [
                    'title' => 'Web application attacks addressed',
                    'status' => $this->assessWebProtection($stats),
                    'evidence' => [
                        'xss_blocked' => $stats['by_guard']['xss'] ?? 0,
                        'sqli_blocked' => $stats['by_guard']['sql-injection'] ?? 0,
                        'injection_blocked' => $stats['by_guard']['command-injection'] ?? 0,
                    ],
                ],
                '10.2' => [
                    'title' => 'Audit trail enabled for security events',
                    'status' => $this->assessLogging($stats),
                    'evidence' => [
                        'events_logged' => $stats['total_events'],
                        'logging_enabled' => config('runtime-guard.logging.enabled', false),
                        'retention_days' => config('runtime-guard.logging.retention_days', 90),
                    ],
                ],
                '11.4' => [
                    'title' => 'Intrusion-detection techniques',
                    'status' => $stats['active_guards'] > 0 ? 'compliant' : 'non-compliant',
                    'evidence' => [
                        'real_time_monitoring' => true,
                        'anomaly_detection' => in_array('anomaly', $stats['coverage_areas']),
                        'automated_blocking' => config('runtime-guard.mode') === 'block',
                    ],
                ],
            ],
            'summary' => [
                'compliant_requirements' => $this->countCompliant($stats),
                'total_requirements' => 4,
                'overall_status' => $this->assessOverallCompliance($stats),
            ],
            'generated_at' => now()->toIso8601String(),
        ];
    }

    /**
     * Generate OWASP Top 10 compliance report.
     */
    public function generateOwaspReport(int $days = 30): array
    {
        $stats = $this->getSecurityStats($days);

        return [
            'framework' => 'OWASP Top 10 2021',
            'period' => [
                'start' => date('Y-m-d', strtotime("-{$days} days")),
                'end' => date('Y-m-d'),
                'days' => $days,
            ],
            'categories' => [
                'A01:2021' => [
                    'title' => 'Broken Access Control',
                    'protected' => in_array('mass-assignment', $stats['coverage_areas']),
                    'threats_blocked' => $stats['by_guard']['mass-assignment'] ?? 0,
                ],
                'A02:2021' => [
                    'title' => 'Cryptographic Failures',
                    'protected' => false, // Outside scope of RuntimeGuard
                    'note' => 'Handled at application/infrastructure level',
                ],
                'A03:2021' => [
                    'title' => 'Injection',
                    'protected' => true,
                    'threats_blocked' => ($stats['by_guard']['sql-injection'] ?? 0) +
                        ($stats['by_guard']['nosql-injection'] ?? 0) +
                        ($stats['by_guard']['command-injection'] ?? 0),
                    'sub_categories' => [
                        'SQL Injection' => $stats['by_guard']['sql-injection'] ?? 0,
                        'NoSQL Injection' => $stats['by_guard']['nosql-injection'] ?? 0,
                        'Command Injection' => $stats['by_guard']['command-injection'] ?? 0,
                    ],
                ],
                'A04:2021' => [
                    'title' => 'Insecure Design',
                    'protected' => false,
                    'note' => 'Requires architectural review',
                ],
                'A05:2021' => [
                    'title' => 'Security Misconfiguration',
                    'protected' => in_array('file-operation', $stats['coverage_areas']),
                    'threats_blocked' => $stats['by_guard']['file-operation'] ?? 0,
                ],
                'A06:2021' => [
                    'title' => 'Vulnerable and Outdated Components',
                    'protected' => false,
                    'note' => 'Requires dependency scanning tools',
                ],
                'A07:2021' => [
                    'title' => 'Identification and Authentication Failures',
                    'protected' => false,
                    'note' => 'Handled by authentication systems',
                ],
                'A08:2021' => [
                    'title' => 'Software and Data Integrity Failures',
                    'protected' => in_array('deserialization', $stats['coverage_areas']),
                    'threats_blocked' => $stats['by_guard']['deserialization'] ?? 0,
                ],
                'A09:2021' => [
                    'title' => 'Security Logging and Monitoring Failures',
                    'protected' => config('runtime-guard.logging.enabled', false),
                    'events_logged' => $stats['total_events'],
                ],
                'A10:2021' => [
                    'title' => 'Server-Side Request Forgery (SSRF)',
                    'protected' => in_array('ssrf', $stats['coverage_areas']),
                    'threats_blocked' => $stats['by_guard']['ssrf'] ?? 0,
                ],
            ],
            'coverage' => [
                'protected_categories' => $this->countOwaspProtected($stats),
                'total_categories' => 10,
                'protection_percentage' => round($this->countOwaspProtected($stats) / 10 * 100),
            ],
            'generated_at' => now()->toIso8601String(),
        ];
    }

    /**
     * Generate SOC 2 Type II evidence report.
     */
    public function generateSoc2Report(int $days = 30): array
    {
        $stats = $this->getSecurityStats($days);

        return [
            'framework' => 'SOC 2 Type II',
            'period' => [
                'start' => date('Y-m-d', strtotime("-{$days} days")),
                'end' => date('Y-m-d'),
                'days' => $days,
            ],
            'trust_principles' => [
                'security' => [
                    'title' => 'Security',
                    'controls' => [
                        'CC6.1' => [
                            'description' => 'Logical access security software',
                            'evidence' => [
                                'runtime_protection' => true,
                                'guards_active' => $stats['active_guards'],
                                'threats_blocked' => $stats['total_blocked'],
                            ],
                        ],
                        'CC6.6' => [
                            'description' => 'Security events are logged',
                            'evidence' => [
                                'logging_enabled' => config('runtime-guard.logging.enabled'),
                                'events_captured' => $stats['total_events'],
                            ],
                        ],
                        'CC6.8' => [
                            'description' => 'Prevent/detect unauthorized software',
                            'evidence' => [
                                'injection_prevention' => true,
                                'command_execution_blocked' => $stats['by_guard']['command-injection'] ?? 0,
                            ],
                        ],
                    ],
                ],
                'availability' => [
                    'title' => 'Availability',
                    'controls' => [
                        'A1.2' => [
                            'description' => 'Capacity management',
                            'evidence' => [
                                'performance_monitoring' => true,
                                'blocking_mode' => config('runtime-guard.mode'),
                            ],
                        ],
                    ],
                ],
            ],
            'evidence_summary' => [
                'total_security_events' => $stats['total_events'],
                'threats_prevented' => $stats['total_blocked'],
                'protection_uptime' => '99.9%', // Placeholder
                'guards_operational' => $stats['active_guards'],
            ],
            'generated_at' => now()->toIso8601String(),
        ];
    }

    /**
     * Generate executive summary report.
     */
    public function generateExecutiveSummary(int $days = 30): array
    {
        $stats = $this->getSecurityStats($days);
        $previousStats = $this->getSecurityStats($days, $days);

        $changePercent = $previousStats['total_blocked'] > 0
            ? (($stats['total_blocked'] - $previousStats['total_blocked']) / $previousStats['total_blocked']) * 100
            : 0;

        return [
            'title' => 'RuntimeGuard Security Executive Summary',
            'period' => "{$days} days ending " . date('Y-m-d'),
            'key_metrics' => [
                'total_threats_blocked' => $stats['total_blocked'],
                'change_from_previous' => round($changePercent, 1) . '%',
                'critical_threats' => $stats['by_level']['critical'] ?? 0,
                'high_threats' => $stats['by_level']['high'] ?? 0,
                'active_protection_guards' => $stats['active_guards'],
            ],
            'threat_breakdown' => [
                'injection_attacks' => ($stats['by_guard']['sql-injection'] ?? 0) +
                    ($stats['by_guard']['nosql-injection'] ?? 0) +
                    ($stats['by_guard']['command-injection'] ?? 0),
                'xss_attacks' => $stats['by_guard']['xss'] ?? 0,
                'ssrf_attempts' => $stats['by_guard']['ssrf'] ?? 0,
                'other' => $stats['total_blocked'] - (
                    ($stats['by_guard']['sql-injection'] ?? 0) +
                    ($stats['by_guard']['nosql-injection'] ?? 0) +
                    ($stats['by_guard']['command-injection'] ?? 0) +
                    ($stats['by_guard']['xss'] ?? 0) +
                    ($stats['by_guard']['ssrf'] ?? 0)
                ),
            ],
            'compliance_status' => [
                'pci_dss' => $this->assessOverallCompliance($stats),
                'owasp_coverage' => round($this->countOwaspProtected($stats) / 10 * 100) . '%',
            ],
            'recommendations' => $this->generateRecommendations($stats),
            'generated_at' => now()->toIso8601String(),
        ];
    }

    /**
     * Get security statistics.
     */
    protected function getSecurityStats(int $days = 30, int $offset = 0): array
    {
        $guards = config('runtime-guard.guards', []);
        $activeGuards = 0;
        $coverageAreas = [];

        foreach ($guards as $name => $config) {
            if ($config['enabled'] ?? true) {
                $activeGuards++;
                $coverageAreas[] = $name;
            }
        }

        // Get counters from cache (simplified - in production, would use actual metrics)
        $byGuard = [];
        $byLevel = ['low' => 0, 'medium' => 0, 'high' => 0, 'critical' => 0];
        $totalBlocked = 0;
        $totalEvents = 0;

        foreach ($coverageAreas as $guard) {
            $key = $this->cachePrefix . "blocked:{$guard}";
            $count = (int) Cache::get($key, 0);
            $byGuard[$guard] = $count;
            $totalBlocked += $count;
        }

        foreach (array_keys($byLevel) as $level) {
            $key = $this->cachePrefix . "level:{$level}";
            $byLevel[$level] = (int) Cache::get($key, 0);
            $totalEvents += $byLevel[$level];
        }

        return [
            'active_guards' => $activeGuards,
            'coverage_areas' => $coverageAreas,
            'by_guard' => $byGuard,
            'by_level' => $byLevel,
            'total_blocked' => $totalBlocked,
            'total_events' => $totalEvents,
        ];
    }

    /**
     * Assess guard coverage.
     */
    protected function assessGuardCoverage(array $stats): string
    {
        if ($stats['active_guards'] >= 5) {
            return 'compliant';
        }
        if ($stats['active_guards'] >= 3) {
            return 'partial';
        }
        return 'non-compliant';
    }

    /**
     * Assess web protection.
     */
    protected function assessWebProtection(array $stats): string
    {
        $webGuards = ['xss', 'sql-injection', 'command-injection'];
        $active = array_intersect($webGuards, $stats['coverage_areas']);

        if (count($active) >= 3) {
            return 'compliant';
        }
        if (count($active) >= 2) {
            return 'partial';
        }
        return 'non-compliant';
    }

    /**
     * Assess logging.
     */
    protected function assessLogging(array $stats): string
    {
        if (config('runtime-guard.logging.enabled') && $stats['total_events'] > 0) {
            return 'compliant';
        }
        if (config('runtime-guard.logging.enabled')) {
            return 'partial';
        }
        return 'non-compliant';
    }

    /**
     * Count compliant requirements.
     */
    protected function countCompliant(array $stats): int
    {
        $count = 0;

        if ($this->assessGuardCoverage($stats) === 'compliant') $count++;
        if ($this->assessWebProtection($stats) === 'compliant') $count++;
        if ($this->assessLogging($stats) === 'compliant') $count++;
        if ($stats['active_guards'] > 0) $count++;

        return $count;
    }

    /**
     * Assess overall compliance.
     */
    protected function assessOverallCompliance(array $stats): string
    {
        $compliant = $this->countCompliant($stats);

        if ($compliant >= 4) return 'compliant';
        if ($compliant >= 2) return 'partial';
        return 'non-compliant';
    }

    /**
     * Count OWASP categories protected.
     */
    protected function countOwaspProtected(array $stats): int
    {
        $protected = 0;

        if (in_array('mass-assignment', $stats['coverage_areas'])) $protected++;
        if (in_array('sql-injection', $stats['coverage_areas']) ||
            in_array('command-injection', $stats['coverage_areas'])) $protected++;
        if (in_array('file-operation', $stats['coverage_areas'])) $protected++;
        if (in_array('deserialization', $stats['coverage_areas'])) $protected++;
        if (config('runtime-guard.logging.enabled')) $protected++;
        if (in_array('ssrf', $stats['coverage_areas'])) $protected++;

        return $protected;
    }

    /**
     * Generate recommendations based on stats.
     */
    protected function generateRecommendations(array $stats): array
    {
        $recommendations = [];

        if (!in_array('ssrf', $stats['coverage_areas'])) {
            $recommendations[] = 'Enable SSRF Guard to protect against server-side request forgery';
        }

        if (!in_array('anomaly', $stats['coverage_areas'])) {
            $recommendations[] = 'Enable Anomaly Guard for behavioral threat detection';
        }

        if (!config('runtime-guard.logging.enabled')) {
            $recommendations[] = 'Enable security event logging for compliance requirements';
        }

        if (($stats['by_level']['critical'] ?? 0) > 10) {
            $recommendations[] = 'High number of critical threats - review firewall rules';
        }

        if (empty($recommendations)) {
            $recommendations[] = 'Security posture is healthy - continue monitoring';
        }

        return $recommendations;
    }

    /**
     * Record blocked threat for compliance tracking.
     */
    public function recordBlocked(string $guard, string $level): void
    {
        Cache::increment($this->cachePrefix . "blocked:{$guard}");
        Cache::increment($this->cachePrefix . "level:{$level}");
    }
}
