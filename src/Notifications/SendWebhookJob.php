<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Queued job for sending webhooks asynchronously.
 */
class SendWebhookJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries;
    public int $backoff;

    public function __construct(
        private array $endpoint,
        private array $payload,
        int $maxRetries = 3,
        int $retryDelayMs = 1000
    ) {
        $this->tries = $maxRetries;
        $this->backoff = (int)($retryDelayMs / 1000);
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        $response = Http::timeout(10)
            ->withHeaders(array_merge(
                ['Content-Type' => 'application/json'],
                $this->endpoint['headers'] ?? []
            ))
            ->post($this->endpoint['url'], $this->payload);

        if (!$response->successful()) {
            Log::warning('RuntimeGuard webhook failed', [
                'url' => $this->endpoint['url'],
                'status' => $response->status(),
            ]);

            throw new \RuntimeException('Webhook failed with status: ' . $response->status());
        }
    }

    /**
     * Handle job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('RuntimeGuard webhook permanently failed', [
            'url' => $this->endpoint['url'],
            'error' => $exception->getMessage(),
        ]);
    }
}
