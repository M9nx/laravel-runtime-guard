<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Performance;

/**
 * JIT Pattern Warmer.
 *
 * Pre-compiles and warms up PCRE patterns to ensure JIT optimization.
 */
class JitWarmer
{
    protected array $patterns = [];
    protected array $warmedPatterns = [];
    protected bool $jitAvailable;

    public function __construct()
    {
        $this->jitAvailable = $this->checkJitAvailability();
    }

    /**
     * Check if PCRE JIT is available.
     */
    protected function checkJitAvailability(): bool
    {
        if (!defined('PREG_JIT_STACKLIMIT_ERROR')) {
            return false;
        }

        // Check pcre.jit ini setting
        $jitSetting = ini_get('pcre.jit');

        return $jitSetting !== '0' && $jitSetting !== false;
    }

    /**
     * Check if JIT is available.
     */
    public function isJitAvailable(): bool
    {
        return $this->jitAvailable;
    }

    /**
     * Register patterns for warming.
     */
    public function registerPatterns(array $patterns): self
    {
        foreach ($patterns as $name => $pattern) {
            $this->patterns[$name] = $pattern;
        }

        return $this;
    }

    /**
     * Warm all registered patterns.
     */
    public function warmAll(): array
    {
        $results = [];

        foreach ($this->patterns as $name => $pattern) {
            $results[$name] = $this->warmPattern($name, $pattern);
        }

        return $results;
    }

    /**
     * Warm a single pattern.
     */
    public function warmPattern(string $name, string $pattern): array
    {
        $result = [
            'name' => $name,
            'pattern' => $pattern,
            'valid' => false,
            'jit_compiled' => false,
            'warm_time_us' => 0,
            'test_match_time_us' => 0,
        ];

        // Validate pattern
        $start = hrtime(true);
        $valid = @preg_match($pattern, '') !== false;
        $result['valid'] = $valid;

        if (!$valid) {
            $result['error'] = preg_last_error_msg();
            return $result;
        }

        // Warm up pattern with multiple matches
        $testStrings = $this->generateWarmupStrings();

        foreach ($testStrings as $testString) {
            preg_match($pattern, $testString);
        }

        $result['warm_time_us'] = (hrtime(true) - $start) / 1000;

        // Benchmark after warming
        $start = hrtime(true);
        for ($i = 0; $i < 100; $i++) {
            preg_match($pattern, $testStrings[0]);
        }
        $result['test_match_time_us'] = (hrtime(true) - $start) / 1000 / 100;

        // Check JIT compilation status
        $result['jit_compiled'] = $this->jitAvailable && $this->isPatternJitCompiled($pattern);

        $this->warmedPatterns[$name] = $result;

        return $result;
    }

    /**
     * Generate warmup test strings.
     */
    protected function generateWarmupStrings(): array
    {
        return [
            '',
            'a',
            'test',
            str_repeat('a', 100),
            str_repeat('ab', 50),
            'SELECT * FROM users',
            '<script>alert(1)</script>',
            '<?php echo "test"; ?>',
            '{"key": "value"}',
            base64_encode(str_repeat('x', 100)),
            str_repeat('a', 1000),
            implode(' ', range('a', 'z')),
            str_repeat('0123456789', 100),
        ];
    }

    /**
     * Check if pattern was JIT compiled.
     */
    protected function isPatternJitCompiled(string $pattern): bool
    {
        if (!$this->jitAvailable) {
            return false;
        }

        // Patterns with certain features won't JIT compile
        $nonJitFeatures = [
            '(?R)',      // Recursion
            '(?P>',      // Named recursion
            '(?1)',      // Subroutine reference
            '\K',        // Reset match start
            '(*SKIP)',   // Backtracking verbs
            '(*FAIL)',
            '(*F)',
            '(*PRUNE)',
            '(*ACCEPT)',
            '(*THEN)',
            '(?C)',      // Callouts
        ];

        foreach ($nonJitFeatures as $feature) {
            if (str_contains($pattern, $feature)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get warmed patterns info.
     */
    public function getWarmedPatterns(): array
    {
        return $this->warmedPatterns;
    }

    /**
     * Get warming statistics.
     */
    public function getStatistics(): array
    {
        $total = count($this->warmedPatterns);
        $valid = 0;
        $jitCompiled = 0;
        $totalWarmTime = 0;
        $avgMatchTime = 0;

        foreach ($this->warmedPatterns as $info) {
            if ($info['valid']) {
                $valid++;
            }
            if ($info['jit_compiled']) {
                $jitCompiled++;
            }
            $totalWarmTime += $info['warm_time_us'];
            $avgMatchTime += $info['test_match_time_us'];
        }

        return [
            'total_patterns' => $total,
            'valid_patterns' => $valid,
            'invalid_patterns' => $total - $valid,
            'jit_compiled' => $jitCompiled,
            'jit_ratio' => $total > 0 ? round($jitCompiled / $total * 100, 2) : 0,
            'total_warm_time_ms' => round($totalWarmTime / 1000, 2),
            'avg_match_time_us' => $total > 0 ? round($avgMatchTime / $total, 2) : 0,
            'jit_available' => $this->jitAvailable,
        ];
    }

    /**
     * Optimize pattern for JIT.
     */
    public function optimizePattern(string $pattern): string
    {
        // Add study modifier if not present
        if (!str_contains($pattern, 'S')) {
            // Find the end of pattern and modifiers
            $lastDelim = strrpos($pattern, $pattern[0]);
            if ($lastDelim !== false && $lastDelim !== 0) {
                $modifiers = substr($pattern, $lastDelim + 1);
                if (!str_contains($modifiers, 'S')) {
                    $pattern = substr($pattern, 0, $lastDelim + 1) . 'S' . $modifiers;
                }
            }
        }

        return $pattern;
    }

    /**
     * Batch warm patterns from guards.
     */
    public function warmFromGuards(array $guards): array
    {
        $allResults = [];

        foreach ($guards as $guard) {
            if (method_exists($guard, 'getCompiledPatterns')) {
                $patterns = $guard->getCompiledPatterns();
                foreach ($patterns as $name => $pattern) {
                    $fullName = $guard->getName() . '.' . $name;
                    $allResults[$fullName] = $this->warmPattern($fullName, $pattern);
                }
            }
        }

        return $allResults;
    }
}
