<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Notifications;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Http;
use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Support\InspectionContext;
use Psr\Log\LoggerInterface;

/**
 * Webhook notification dispatcher for security events.
 *
 * Supports multiple endpoints with filtering, batching, and retry logic.
 * Built-in support for Slack, Discord, PagerDuty, and custom endpoints.
 */
class WebhookDispatcher
{
    /**
     * @var array<array{url: string, filters: array, format: string, headers: array}>
     */
    private array $endpoints = [];

    private bool $async;
    private int $batchSize;
    private int $batchTimeoutMs;
    private int $maxRetries;
    private int $retryDelayMs;
    private ?LoggerInterface $logger;

    /**
     * @var array<array{result: GuardResultInterface, context: array}>
     */
    private array $batch = [];
    private ?int $batchStartTime = null;

    public function __construct(array $config = [])
    {
        $this->endpoints = $config['endpoints'] ?? [];
        $this->async = $config['async'] ?? true;
        $this->batchSize = $config['batch_size'] ?? 10;
        $this->batchTimeoutMs = $config['batch_timeout_ms'] ?? 5000;
        $this->maxRetries = $config['max_retries'] ?? 3;
        $this->retryDelayMs = $config['retry_delay_ms'] ?? 1000;
        $this->logger = $config['logger'] ?? null;
    }

    /**
     * Create from configuration.
     */
    public static function fromConfig(array $config, ?LoggerInterface $logger = null): self
    {
        return new self(array_merge($config, ['logger' => $logger]));
    }

    /**
     * Add webhook endpoint.
     */
    public function addEndpoint(
        string $url,
        array $filters = [],
        string $format = 'json',
        array $headers = []
    ): self {
        $this->endpoints[] = [
            'url' => $url,
            'filters' => $filters,
            'format' => $format,
            'headers' => $headers,
        ];

        return $this;
    }

    /**
     * Dispatch security event to webhooks.
     */
    public function dispatch(GuardResultInterface $result, InspectionContext $context): void
    {
        if ($result->passed()) {
            return;
        }

        $event = [
            'result' => $result,
            'context' => $context->toArray(),
        ];

        if ($this->batchSize > 1) {
            $this->addToBatch($event);
        } else {
            $this->sendToEndpoints([$event]);
        }
    }

    /**
     * Add event to batch.
     */
    private function addToBatch(array $event): void
    {
        if ($this->batchStartTime === null) {
            $this->batchStartTime = (int)(microtime(true) * 1000);
        }

        $this->batch[] = $event;

        if ($this->shouldFlushBatch()) {
            $this->flushBatch();
        }
    }

    /**
     * Check if batch should be flushed.
     */
    private function shouldFlushBatch(): bool
    {
        if (count($this->batch) >= $this->batchSize) {
            return true;
        }

        if ($this->batchStartTime !== null) {
            $elapsed = (int)(microtime(true) * 1000) - $this->batchStartTime;
            if ($elapsed >= $this->batchTimeoutMs) {
                return true;
            }
        }

        return false;
    }

    /**
     * Flush pending batch.
     */
    public function flushBatch(): void
    {
        if (empty($this->batch)) {
            return;
        }

        $events = $this->batch;
        $this->batch = [];
        $this->batchStartTime = null;

        $this->sendToEndpoints($events);
    }

    /**
     * Send events to all matching endpoints.
     */
    private function sendToEndpoints(array $events): void
    {
        foreach ($this->endpoints as $endpoint) {
            $filteredEvents = $this->filterEvents($events, $endpoint['filters']);

            if (empty($filteredEvents)) {
                continue;
            }

            $payload = $this->formatPayload($filteredEvents, $endpoint['format']);

            if ($this->async) {
                $this->sendAsync($endpoint, $payload);
            } else {
                $this->sendSync($endpoint, $payload);
            }
        }
    }

    /**
     * Filter events based on endpoint filters.
     */
    private function filterEvents(array $events, array $filters): array
    {
        if (empty($filters)) {
            return $events;
        }

        return array_filter($events, function ($event) use ($filters) {
            $result = $event['result'];

            // Filter by threat level
            if (isset($filters['min_threat_level'])) {
                $minWeight = $this->threatLevelWeight($filters['min_threat_level']);
                if ($result->getThreatLevel()->weight() < $minWeight) {
                    return false;
                }
            }

            // Filter by guard name
            if (isset($filters['guards'])) {
                if (!in_array($result->getGuardName(), $filters['guards'])) {
                    return false;
                }
            }

            // Filter by excluded guards
            if (isset($filters['exclude_guards'])) {
                if (in_array($result->getGuardName(), $filters['exclude_guards'])) {
                    return false;
                }
            }

            return true;
        });
    }

    /**
     * Format payload for endpoint.
     */
    private function formatPayload(array $events, string $format): array
    {
        return match ($format) {
            'slack' => $this->formatSlack($events),
            'discord' => $this->formatDiscord($events),
            'pagerduty' => $this->formatPagerDuty($events),
            'teams' => $this->formatTeams($events),
            default => $this->formatJson($events),
        };
    }

    /**
     * Format as JSON.
     */
    private function formatJson(array $events): array
    {
        return [
            'timestamp' => now()->toIso8601String(),
            'source' => 'runtime-guard',
            'event_count' => count($events),
            'events' => array_map(function ($event) {
                return [
                    'guard' => $event['result']->getGuardName(),
                    'threat_level' => $event['result']->getThreatLevel()->value,
                    'message' => $event['result']->getMessage(),
                    'metadata' => $event['result']->getMetadata(),
                    'context' => $this->sanitizeContext($event['context']),
                ];
            }, $events),
        ];
    }

    /**
     * Format for Slack.
     */
    private function formatSlack(array $events): array
    {
        $blocks = [
            [
                'type' => 'header',
                'text' => [
                    'type' => 'plain_text',
                    'text' => '🛡️ RuntimeGuard Alert',
                ],
            ],
        ];

        foreach (array_slice($events, 0, 10) as $event) {
            $result = $event['result'];
            $emoji = $this->getThreatEmoji($result->getThreatLevel()->value);

            $blocks[] = [
                'type' => 'section',
                'text' => [
                    'type' => 'mrkdwn',
                    'text' => sprintf(
                        "%s *%s* - %s\n`%s`",
                        $emoji,
                        strtoupper($result->getThreatLevel()->value),
                        $result->getGuardName(),
                        $result->getMessage()
                    ),
                ],
            ];
        }

        if (count($events) > 10) {
            $blocks[] = [
                'type' => 'context',
                'elements' => [
                    ['type' => 'mrkdwn', 'text' => sprintf('_...and %d more events_', count($events) - 10)],
                ],
            ];
        }

        return ['blocks' => $blocks];
    }

    /**
     * Format for Discord.
     */
    private function formatDiscord(array $events): array
    {
        $embeds = [];

        foreach (array_slice($events, 0, 10) as $event) {
            $result = $event['result'];

            $embeds[] = [
                'title' => '🛡️ ' . $result->getGuardName(),
                'description' => $result->getMessage(),
                'color' => $this->getThreatColor($result->getThreatLevel()->value),
                'fields' => [
                    ['name' => 'Threat Level', 'value' => strtoupper($result->getThreatLevel()->value), 'inline' => true],
                    ['name' => 'Time', 'value' => now()->toIso8601String(), 'inline' => true],
                ],
            ];
        }

        return ['embeds' => $embeds];
    }

    /**
     * Format for PagerDuty.
     */
    private function formatPagerDuty(array $events): array
    {
        $highestSeverity = 'info';
        foreach ($events as $event) {
            $level = $event['result']->getThreatLevel()->value;
            if ($level === 'critical') $highestSeverity = 'critical';
            elseif ($level === 'high' && $highestSeverity !== 'critical') $highestSeverity = 'error';
            elseif ($level === 'medium' && !in_array($highestSeverity, ['critical', 'error'])) $highestSeverity = 'warning';
        }

        return [
            'routing_key' => '', // Set in headers
            'event_action' => 'trigger',
            'payload' => [
                'summary' => sprintf('RuntimeGuard: %d security events detected', count($events)),
                'severity' => $highestSeverity,
                'source' => config('app.name', 'Laravel'),
                'custom_details' => [
                    'events' => array_map(fn($e) => [
                        'guard' => $e['result']->getGuardName(),
                        'message' => $e['result']->getMessage(),
                    ], array_slice($events, 0, 20)),
                ],
            ],
        ];
    }

    /**
     * Format for Microsoft Teams.
     */
    private function formatTeams(array $events): array
    {
        $facts = [];
        foreach (array_slice($events, 0, 10) as $event) {
            $result = $event['result'];
            $facts[] = [
                'name' => $result->getGuardName(),
                'value' => sprintf('[%s] %s', strtoupper($result->getThreatLevel()->value), $result->getMessage()),
            ];
        }

        return [
            '@type' => 'MessageCard',
            '@context' => 'http://schema.org/extensions',
            'themeColor' => 'FF0000',
            'summary' => 'RuntimeGuard Security Alert',
            'sections' => [
                [
                    'activityTitle' => '🛡️ RuntimeGuard Alert',
                    'activitySubtitle' => sprintf('%d security events detected', count($events)),
                    'facts' => $facts,
                ],
            ],
        ];
    }

    /**
     * Send webhook synchronously.
     */
    private function sendSync(array $endpoint, array $payload): bool
    {
        $attempts = 0;

        while ($attempts < $this->maxRetries) {
            try {
                $response = Http::timeout(10)
                    ->withHeaders(array_merge(
                        ['Content-Type' => 'application/json'],
                        $endpoint['headers'] ?? []
                    ))
                    ->post($endpoint['url'], $payload);

                if ($response->successful()) {
                    return true;
                }

                $this->logger?->warning('Webhook failed', [
                    'url' => $endpoint['url'],
                    'status' => $response->status(),
                    'attempt' => $attempts + 1,
                ]);
            } catch (\Throwable $e) {
                $this->logger?->error('Webhook exception', [
                    'url' => $endpoint['url'],
                    'error' => $e->getMessage(),
                    'attempt' => $attempts + 1,
                ]);
            }

            $attempts++;

            if ($attempts < $this->maxRetries) {
                usleep($this->retryDelayMs * 1000 * $attempts);
            }
        }

        return false;
    }

    /**
     * Send webhook asynchronously via queue.
     */
    private function sendAsync(array $endpoint, array $payload): void
    {
        dispatch(new SendWebhookJob($endpoint, $payload, $this->maxRetries, $this->retryDelayMs))
            ->onQueue('runtime-guard-webhooks');
    }

    /**
     * Sanitize context for external transmission.
     */
    private function sanitizeContext(array $context): array
    {
        unset($context['input']); // Never send raw input externally

        // Mask sensitive fields
        if (isset($context['ip'])) {
            $context['ip'] = $this->maskIp($context['ip']);
        }

        return $context;
    }

    /**
     * Mask IP address.
     */
    private function maskIp(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            return $parts[0] . '.' . $parts[1] . '.xxx.xxx';
        }
        return substr($ip, 0, 10) . '...';
    }

    /**
     * Get threat level weight.
     */
    private function threatLevelWeight(string $level): int
    {
        return match ($level) {
            'critical' => 100,
            'high' => 75,
            'medium' => 50,
            'low' => 25,
            default => 0,
        };
    }

    /**
     * Get threat emoji.
     */
    private function getThreatEmoji(string $level): string
    {
        return match ($level) {
            'critical' => '🔴',
            'high' => '🟠',
            'medium' => '🟡',
            'low' => '🟢',
            default => '⚪',
        };
    }

    /**
     * Get threat color for Discord.
     */
    private function getThreatColor(string $level): int
    {
        return match ($level) {
            'critical' => 0xFF0000,
            'high' => 0xFF8C00,
            'medium' => 0xFFD700,
            'low' => 0x32CD32,
            default => 0x808080,
        };
    }
}
