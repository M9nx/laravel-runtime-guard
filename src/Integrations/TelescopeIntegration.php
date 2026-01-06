<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Integrations;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use Laravel\Telescope\Telescope;
use Laravel\Telescope\IncomingEntry;

/**
 * Laravel Telescope Integration.
 *
 * Records security events in Telescope for debugging and analysis.
 */
class TelescopeIntegration
{
    protected bool $enabled;
    protected array $recordLevels;

    public function __construct()
    {
        $this->enabled = $this->isTelescopeAvailable() && config('runtime-guard.integrations.telescope.enabled', true);
        $this->recordLevels = config('runtime-guard.integrations.telescope.record_levels', [
            'low', 'medium', 'high', 'critical',
        ]);
    }

    /**
     * Check if Telescope is available.
     */
    protected function isTelescopeAvailable(): bool
    {
        return class_exists(Telescope::class) && Telescope::isRecording();
    }

    /**
     * Record a guard result in Telescope.
     */
    public function record(string $guardName, GuardResultInterface $result, array $context = []): void
    {
        if (!$this->enabled) {
            return;
        }

        // Check if we should record this level
        $level = strtolower($result->getThreatLevel()?->name ?? 'unknown');
        if (!in_array($level, $this->recordLevels)) {
            return;
        }

        $this->recordEntry([
            'guard' => $guardName,
            'passed' => $result->passed(),
            'threat_level' => $level,
            'message' => $result->getMessage(),
            'details' => $result->getDetails(),
            'context' => $this->sanitizeContext($context),
            'timestamp' => now()->toIso8601String(),
        ]);
    }

    /**
     * Record a security event.
     */
    public function recordEvent(string $event, array $data = []): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->recordEntry([
            'type' => 'security_event',
            'event' => $event,
            'data' => $this->sanitizeContext($data),
            'timestamp' => now()->toIso8601String(),
        ]);
    }

    /**
     * Record entry in Telescope.
     */
    protected function recordEntry(array $content): void
    {
        try {
            Telescope::recordCache(IncomingEntry::make([
                'type' => 'runtime-guard',
                'content' => $content,
            ])->tags(['runtime-guard', $content['guard'] ?? 'event']));
        } catch (\Throwable $e) {
            // Silently fail if Telescope recording fails
        }
    }

    /**
     * Sanitize context data for recording.
     */
    protected function sanitizeContext(array $context): array
    {
        $sanitized = [];
        $sensitiveKeys = ['password', 'token', 'secret', 'key', 'auth', 'credential'];

        foreach ($context as $key => $value) {
            // Check for sensitive keys
            $isSensitive = false;
            foreach ($sensitiveKeys as $sensitive) {
                if (stripos($key, $sensitive) !== false) {
                    $isSensitive = true;
                    break;
                }
            }

            if ($isSensitive) {
                $sanitized[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $sanitized[$key] = $this->sanitizeContext($value);
            } elseif (is_string($value) && strlen($value) > 1000) {
                $sanitized[$key] = substr($value, 0, 1000) . '...[truncated]';
            } else {
                $sanitized[$key] = $value;
            }
        }

        return $sanitized;
    }

    /**
     * Check if integration is enabled.
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * Disable integration.
     */
    public function disable(): void
    {
        $this->enabled = false;
    }

    /**
     * Enable integration.
     */
    public function enable(): void
    {
        $this->enabled = $this->isTelescopeAvailable();
    }
}
