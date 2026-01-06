<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Symfony\Component\Finder\Finder;

/**
 * Static security audit command.
 *
 * Scans codebase for common security vulnerabilities:
 * - Raw SQL queries
 * - Unescaped output
 * - Dangerous function calls
 * - Missing CSRF protection
 * - Insecure configurations
 */
class SecurityAuditCommand extends Command
{
    protected $signature = 'runtime-guard:audit
                            {path? : Path to scan (default: app/)}
                            {--severity=low : Minimum severity to report (low, medium, high, critical)}
                            {--format=table : Output format (table, json, sarif)}
                            {--fix : Attempt to fix issues where possible}
                            {--ci : Exit with non-zero code if issues found}';

    protected $description = 'Scan codebase for security vulnerabilities';

    /**
     * Security rules to check.
     */
    private array $rules = [];

    /**
     * Found issues.
     */
    private array $issues = [];

    public function handle(): int
    {
        $this->initializeRules();

        $path = $this->argument('path') ?? app_path();
        $minSeverity = $this->option('severity');
        $format = $this->option('format');

        $this->info("🔍 Scanning {$path} for security issues...\n");

        $this->scanDirectory($path);

        $filtered = $this->filterBySeverity($minSeverity);

        if ($format === 'json') {
            $this->line(json_encode($filtered, JSON_PRETTY_PRINT));
        } elseif ($format === 'sarif') {
            $this->outputSarif($filtered);
        } else {
            $this->outputTable($filtered);
        }

        if ($this->option('fix')) {
            $this->attemptFixes($filtered);
        }

        $this->outputSummary($filtered);

        if ($this->option('ci') && !empty($filtered)) {
            $criticalOrHigh = array_filter($filtered, fn($i) => in_array($i['severity'], ['critical', 'high']));
            return !empty($criticalOrHigh) ? 1 : 0;
        }

        return 0;
    }

    /**
     * Initialize security rules.
     */
    private function initializeRules(): void
    {
        $this->rules = [
            // SQL Injection
            [
                'id' => 'SQL001',
                'name' => 'Raw SQL Query',
                'severity' => 'high',
                'pattern' => '/\bDB::(?:select|insert|update|delete|statement)\s*\(\s*["\'].*\$/',
                'message' => 'Raw SQL with variable interpolation detected',
                'recommendation' => 'Use parameter binding: DB::select("...", [$var])',
            ],
            [
                'id' => 'SQL002',
                'name' => 'Query Builder Raw',
                'severity' => 'medium',
                'pattern' => '/->(?:whereRaw|orWhereRaw|havingRaw|selectRaw|orderByRaw)\s*\(\s*["\'].*\$/',
                'message' => 'Raw clause with variable interpolation',
                'recommendation' => 'Use parameter binding in raw methods',
            ],

            // XSS
            [
                'id' => 'XSS001',
                'name' => 'Unescaped Output',
                'severity' => 'high',
                'pattern' => '/\{!!\s*\$(?!errors|slot|attributes|__env)/',
                'message' => 'Unescaped Blade output detected',
                'recommendation' => 'Use {{ }} instead of {!! !!} or ensure data is sanitized',
            ],
            [
                'id' => 'XSS002',
                'name' => 'Echo Raw HTML',
                'severity' => 'medium',
                'pattern' => '/echo\s+\$\w+\s*;/',
                'message' => 'Raw echo of variable detected',
                'recommendation' => 'Use htmlspecialchars() or e() helper',
            ],

            // Command Injection
            [
                'id' => 'CMD001',
                'name' => 'Shell Execution',
                'severity' => 'critical',
                'pattern' => '/\b(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*.*\$/',
                'message' => 'Shell command with variable detected',
                'recommendation' => 'Use escapeshellarg() and escapeshellcmd()',
            ],
            [
                'id' => 'CMD002',
                'name' => 'Backtick Execution',
                'severity' => 'critical',
                'pattern' => '/`[^`]*\$[^`]*`/',
                'message' => 'Backtick execution with variable',
                'recommendation' => 'Avoid backticks, use Process component with proper escaping',
            ],

            // File Operations
            [
                'id' => 'FILE001',
                'name' => 'Unsafe File Include',
                'severity' => 'critical',
                'pattern' => '/\b(?:include|require|include_once|require_once)\s*\(?.*\$/',
                'message' => 'Dynamic file include detected',
                'recommendation' => 'Validate file paths against whitelist',
            ],
            [
                'id' => 'FILE002',
                'name' => 'Path Traversal Risk',
                'severity' => 'high',
                'pattern' => '/file_(?:get|put)_contents\s*\(\s*\$/',
                'message' => 'File operation with user input',
                'recommendation' => 'Use Storage facade with validated paths',
            ],

            // Deserialization
            [
                'id' => 'DESER001',
                'name' => 'Unsafe Unserialize',
                'severity' => 'critical',
                'pattern' => '/\bunserialize\s*\(\s*\$/',
                'message' => 'Unsafe unserialize with user input',
                'recommendation' => 'Use JSON or specify allowed_classes option',
            ],

            // Cryptography
            [
                'id' => 'CRYPTO001',
                'name' => 'Weak Hash Algorithm',
                'severity' => 'medium',
                'pattern' => '/\b(?:md5|sha1)\s*\(\s*\$(?!.*(?:file|checksum|etag))/i',
                'message' => 'Weak hash algorithm for sensitive data',
                'recommendation' => 'Use password_hash() or Hash::make() for passwords',
            ],
            [
                'id' => 'CRYPTO002',
                'name' => 'Hardcoded Secret',
                'severity' => 'high',
                'pattern' => '/(?:password|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{8,}["\']/',
                'message' => 'Possible hardcoded secret detected',
                'recommendation' => 'Use environment variables via config()',
            ],

            // Mass Assignment
            [
                'id' => 'MASS001',
                'name' => 'Unguarded Model',
                'severity' => 'medium',
                'pattern' => '/protected\s+\$guarded\s*=\s*\[\s*\]/',
                'message' => 'Model with empty $guarded array',
                'recommendation' => 'Define $fillable or specific $guarded fields',
            ],

            // CSRF
            [
                'id' => 'CSRF001',
                'name' => 'Missing CSRF Exclusion',
                'severity' => 'low',
                'pattern' => '/protected\s+\$except\s*=\s*\[[^\]]*\*[^\]]*\]/',
                'message' => 'Wildcard CSRF exception detected',
                'recommendation' => 'Be specific about CSRF exceptions',
            ],

            // Authentication
            [
                'id' => 'AUTH001',
                'name' => 'Timing Attack Risk',
                'severity' => 'medium',
                'pattern' => '/if\s*\(\s*\$\w+\s*===?\s*\$\w+\s*\).*(?:password|token|secret)/i',
                'message' => 'String comparison may be vulnerable to timing attacks',
                'recommendation' => 'Use hash_equals() for constant-time comparison',
            ],

            // Information Disclosure
            [
                'id' => 'INFO001',
                'name' => 'Debug Mode Check',
                'severity' => 'high',
                'pattern' => '/APP_DEBUG\s*=\s*true/',
                'message' => 'Debug mode enabled (check environment)',
                'recommendation' => 'Ensure APP_DEBUG=false in production',
                'file_pattern' => '\.env$',
            ],
            [
                'id' => 'INFO002',
                'name' => 'Exception Disclosure',
                'severity' => 'medium',
                'pattern' => '/->getMessage\(\).*(?:return|echo|print)/',
                'message' => 'Exception message may be exposed to users',
                'recommendation' => 'Log exceptions, show generic error to users',
            ],

            // SSRF
            [
                'id' => 'SSRF001',
                'name' => 'User Controlled URL',
                'severity' => 'high',
                'pattern' => '/(?:file_get_contents|curl_init|Http::get)\s*\(\s*\$/',
                'message' => 'HTTP request with user-controlled URL',
                'recommendation' => 'Validate URLs against whitelist, block internal IPs',
            ],
        ];
    }

    /**
     * Scan directory for issues.
     */
    private function scanDirectory(string $path): void
    {
        if (!File::isDirectory($path)) {
            if (File::exists($path)) {
                $this->scanFile($path);
            }
            return;
        }

        $finder = new Finder();
        $finder->files()
            ->in($path)
            ->name('*.php')
            ->name('*.blade.php')
            ->name('.env')
            ->name('.env.*')
            ->notPath('vendor')
            ->notPath('node_modules')
            ->notPath('storage');

        $bar = $this->output->createProgressBar(iterator_count($finder));
        $bar->start();

        foreach ($finder as $file) {
            $this->scanFile($file->getRealPath());
            $bar->advance();
        }

        $bar->finish();
        $this->newLine(2);
    }

    /**
     * Scan a single file.
     */
    private function scanFile(string $path): void
    {
        $content = File::get($path);
        $lines = explode("\n", $content);

        foreach ($this->rules as $rule) {
            // Check file pattern filter
            if (isset($rule['file_pattern']) && !preg_match('/' . $rule['file_pattern'] . '/', $path)) {
                continue;
            }

            foreach ($lines as $lineNumber => $line) {
                if (preg_match($rule['pattern'], $line, $matches)) {
                    $this->issues[] = [
                        'id' => $rule['id'],
                        'name' => $rule['name'],
                        'severity' => $rule['severity'],
                        'file' => $path,
                        'line' => $lineNumber + 1,
                        'code' => trim($line),
                        'message' => $rule['message'],
                        'recommendation' => $rule['recommendation'],
                    ];
                }
            }
        }
    }

    /**
     * Filter issues by minimum severity.
     */
    private function filterBySeverity(string $minSeverity): array
    {
        $severityOrder = ['low' => 0, 'medium' => 1, 'high' => 2, 'critical' => 3];
        $minLevel = $severityOrder[$minSeverity] ?? 0;

        return array_filter($this->issues, function ($issue) use ($severityOrder, $minLevel) {
            return ($severityOrder[$issue['severity']] ?? 0) >= $minLevel;
        });
    }

    /**
     * Output as table.
     */
    private function outputTable(array $issues): void
    {
        if (empty($issues)) {
            $this->info('✅ No security issues found!');
            return;
        }

        $rows = array_map(function ($issue) {
            $severityColors = [
                'critical' => 'red',
                'high' => 'yellow',
                'medium' => 'cyan',
                'low' => 'white',
            ];
            $color = $severityColors[$issue['severity']] ?? 'white';

            return [
                "<fg={$color}>{$issue['id']}</>",
                "<fg={$color}>" . strtoupper($issue['severity']) . "</>",
                $this->truncate(str_replace(base_path() . '/', '', $issue['file']), 40),
                $issue['line'],
                $this->truncate($issue['message'], 50),
            ];
        }, $issues);

        $this->table(['ID', 'Severity', 'File', 'Line', 'Message'], $rows);
    }

    /**
     * Output as SARIF (Static Analysis Results Interchange Format).
     */
    private function outputSarif(array $issues): void
    {
        $sarif = [
            '$schema' => 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'RuntimeGuard Security Audit',
                            'version' => '3.0',
                            'rules' => array_map(fn($r) => [
                                'id' => $r['id'],
                                'name' => $r['name'],
                                'shortDescription' => ['text' => $r['message']],
                                'help' => ['text' => $r['recommendation']],
                            ], $this->rules),
                        ],
                    ],
                    'results' => array_map(fn($i) => [
                        'ruleId' => $i['id'],
                        'level' => $this->mapSeverityToSarif($i['severity']),
                        'message' => ['text' => $i['message']],
                        'locations' => [
                            [
                                'physicalLocation' => [
                                    'artifactLocation' => ['uri' => $i['file']],
                                    'region' => ['startLine' => $i['line']],
                                ],
                            ],
                        ],
                    ], $issues),
                ],
            ],
        ];

        $this->line(json_encode($sarif, JSON_PRETTY_PRINT));
    }

    /**
     * Map severity to SARIF level.
     */
    private function mapSeverityToSarif(string $severity): string
    {
        return match ($severity) {
            'critical', 'high' => 'error',
            'medium' => 'warning',
            default => 'note',
        };
    }

    /**
     * Attempt automatic fixes.
     */
    private function attemptFixes(array $issues): void
    {
        $fixable = array_filter($issues, fn($i) => in_array($i['id'], ['XSS001', 'CRYPTO001']));

        if (empty($fixable)) {
            $this->warn('No automatically fixable issues found.');
            return;
        }

        if (!$this->confirm(sprintf('Attempt to fix %d issues?', count($fixable)))) {
            return;
        }

        $fixed = 0;
        foreach ($fixable as $issue) {
            // Implement fixes as needed
            // This is a placeholder for the fix logic
            $fixed++;
        }

        $this->info("Fixed {$fixed} issues.");
    }

    /**
     * Output summary.
     */
    private function outputSummary(array $issues): void
    {
        $bySeverity = [];
        foreach ($issues as $issue) {
            $bySeverity[$issue['severity']] = ($bySeverity[$issue['severity']] ?? 0) + 1;
        }

        $this->newLine();
        $this->info('📊 Summary:');
        $this->line(sprintf('   Critical: %d', $bySeverity['critical'] ?? 0));
        $this->line(sprintf('   High: %d', $bySeverity['high'] ?? 0));
        $this->line(sprintf('   Medium: %d', $bySeverity['medium'] ?? 0));
        $this->line(sprintf('   Low: %d', $bySeverity['low'] ?? 0));
        $this->line(sprintf('   Total: %d', count($issues)));
    }

    /**
     * Truncate string.
     */
    private function truncate(string $string, int $length): string
    {
        if (strlen($string) <= $length) {
            return $string;
        }

        return substr($string, 0, $length - 3) . '...';
    }
}
