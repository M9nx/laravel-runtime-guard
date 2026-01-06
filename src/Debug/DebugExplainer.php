<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Debug;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Debug Mode with Detailed Explanations.
 *
 * Provides detailed explanations for security decisions when enabled.
 */
class DebugExplainer
{
    protected bool $enabled;
    protected array $explanations = [];
    protected array $inspectionLog = [];

    public function __construct()
    {
        $this->enabled = (bool) config('runtime-guard.debug.enabled', false);
    }

    /**
     * Check if debug mode is enabled.
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * Enable debug mode.
     */
    public function enable(): void
    {
        $this->enabled = true;
    }

    /**
     * Disable debug mode.
     */
    public function disable(): void
    {
        $this->enabled = false;
    }

    /**
     * Log an inspection start.
     */
    public function logInspectionStart(string $guard, mixed $input, array $context): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->inspectionLog[] = [
            'type' => 'start',
            'guard' => $guard,
            'input_type' => gettype($input),
            'input_size' => $this->getInputSize($input),
            'context_keys' => array_keys($context),
            'timestamp' => microtime(true),
            'memory' => memory_get_usage(),
        ];
    }

    /**
     * Log an inspection end.
     */
    public function logInspectionEnd(string $guard, GuardResultInterface $result, float $durationMs): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->inspectionLog[] = [
            'type' => 'end',
            'guard' => $guard,
            'passed' => $result->passed(),
            'threat_level' => $result->getThreatLevel()?->name,
            'message' => $result->getMessage(),
            'duration_ms' => $durationMs,
            'timestamp' => microtime(true),
            'memory' => memory_get_usage(),
        ];
    }

    /**
     * Add an explanation for a guard decision.
     */
    public function explain(string $guard, string $explanation, array $details = []): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->explanations[] = [
            'guard' => $guard,
            'explanation' => $explanation,
            'details' => $details,
            'timestamp' => microtime(true),
        ];
    }

    /**
     * Explain why a pattern matched.
     */
    public function explainMatch(string $guard, string $pattern, string $matched, string $input): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->explain($guard, "Pattern matched: {$pattern}", [
            'pattern' => $pattern,
            'matched_text' => $matched,
            'match_position' => strpos($input, $matched),
            'surrounding_context' => $this->getSurroundingContext($input, $matched),
        ]);
    }

    /**
     * Explain why input passed.
     */
    public function explainPass(string $guard, string $reason = ''): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->explain($guard, "Input passed inspection" . ($reason ? ": {$reason}" : ''), [
            'result' => 'pass',
        ]);
    }

    /**
     * Explain a threat detection.
     */
    public function explainThreat(
        string $guard,
        ThreatLevel $level,
        string $reason,
        array $evidence = []
    ): void {
        if (!$this->enabled) {
            return;
        }

        $this->explain($guard, "Threat detected: {$reason}", [
            'result' => 'threat',
            'threat_level' => $level->name,
            'threat_level_value' => $level->value,
            'evidence' => $evidence,
            'recommended_action' => $this->getRecommendedAction($level),
        ]);
    }

    /**
     * Get all explanations.
     */
    public function getExplanations(): array
    {
        return $this->explanations;
    }

    /**
     * Get inspection log.
     */
    public function getInspectionLog(): array
    {
        return $this->inspectionLog;
    }

    /**
     * Get a summary of all inspections.
     */
    public function getSummary(): array
    {
        $guards = [];
        $totalDuration = 0;

        foreach ($this->inspectionLog as $log) {
            if ($log['type'] === 'end') {
                $guard = $log['guard'];
                if (!isset($guards[$guard])) {
                    $guards[$guard] = [
                        'inspections' => 0,
                        'passed' => 0,
                        'blocked' => 0,
                        'total_duration_ms' => 0,
                    ];
                }

                $guards[$guard]['inspections']++;
                $guards[$guard]['total_duration_ms'] += $log['duration_ms'];

                if ($log['passed']) {
                    $guards[$guard]['passed']++;
                } else {
                    $guards[$guard]['blocked']++;
                }

                $totalDuration += $log['duration_ms'];
            }
        }

        return [
            'total_inspections' => count(array_filter($this->inspectionLog, fn($l) => $l['type'] === 'end')),
            'total_duration_ms' => round($totalDuration, 3),
            'explanations_count' => count($this->explanations),
            'guards' => $guards,
        ];
    }

    /**
     * Format explanations as human-readable text.
     */
    public function formatAsText(): string
    {
        if (empty($this->explanations)) {
            return "No explanations recorded.";
        }

        $output = "=== RuntimeGuard Debug Explanations ===\n\n";

        foreach ($this->explanations as $i => $exp) {
            $output .= sprintf(
                "[%d] Guard: %s\n    %s\n",
                $i + 1,
                $exp['guard'],
                $exp['explanation']
            );

            if (!empty($exp['details'])) {
                $output .= "    Details:\n";
                foreach ($exp['details'] as $key => $value) {
                    $formatted = is_array($value) ? json_encode($value) : $value;
                    $output .= "      - {$key}: {$formatted}\n";
                }
            }

            $output .= "\n";
        }

        // Add summary
        $summary = $this->getSummary();
        $output .= "=== Summary ===\n";
        $output .= sprintf("Total inspections: %d\n", $summary['total_inspections']);
        $output .= sprintf("Total duration: %.3f ms\n", $summary['total_duration_ms']);

        return $output;
    }

    /**
     * Clear all logs and explanations.
     */
    public function clear(): void
    {
        $this->explanations = [];
        $this->inspectionLog = [];
    }

    /**
     * Get input size for logging.
     */
    protected function getInputSize(mixed $input): int
    {
        if (is_string($input)) {
            return strlen($input);
        }

        if (is_array($input)) {
            return strlen(json_encode($input) ?: '');
        }

        return 0;
    }

    /**
     * Get surrounding context for a match.
     */
    protected function getSurroundingContext(string $input, string $matched, int $chars = 30): string
    {
        $pos = strpos($input, $matched);
        if ($pos === false) {
            return '';
        }

        $start = max(0, $pos - $chars);
        $length = strlen($matched) + ($chars * 2);

        $context = substr($input, $start, $length);

        // Add ellipsis if truncated
        if ($start > 0) {
            $context = '...' . $context;
        }
        if ($start + $length < strlen($input)) {
            $context .= '...';
        }

        return $context;
    }

    /**
     * Get recommended action based on threat level.
     */
    protected function getRecommendedAction(ThreatLevel $level): string
    {
        return match ($level) {
            ThreatLevel::CRITICAL => 'Block immediately and alert security team',
            ThreatLevel::HIGH => 'Block request and log for review',
            ThreatLevel::MEDIUM => 'Log and consider blocking based on context',
            ThreatLevel::LOW => 'Log for monitoring, usually safe to allow',
            default => 'Review and determine appropriate action',
        };
    }
}
