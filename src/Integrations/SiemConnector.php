<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Integrations;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Support\InspectionContext;
use Psr\Log\LoggerInterface;

/**
 * SIEM (Security Information and Event Management) connector.
 *
 * Supports multiple SIEM formats:
 * - CEF (Common Event Format) - ArcSight, QRadar
 * - LEEF (Log Event Extended Format) - QRadar
 * - Splunk HEC (HTTP Event Collector)
 * - Elastic Common Schema (ECS)
 * - Generic JSON
 */
class SiemConnector
{
    public const FORMAT_CEF = 'cef';
    public const FORMAT_LEEF = 'leef';
    public const FORMAT_SPLUNK = 'splunk';
    public const FORMAT_ELASTIC = 'elastic';
    public const FORMAT_JSON = 'json';

    private string $format;
    private ?string $endpoint;
    private array $headers;
    private ?LoggerInterface $logger;
    private string $vendor = 'Mounir';
    private string $product = 'RuntimeGuard';
    private string $version = '3.0';

    public function __construct(array $config = [])
    {
        $this->format = $config['format'] ?? self::FORMAT_JSON;
        $this->endpoint = $config['endpoint'] ?? null;
        $this->headers = $config['headers'] ?? [];
        $this->logger = $config['logger'] ?? null;
        $this->vendor = $config['vendor'] ?? 'Mounir';
        $this->product = $config['product'] ?? 'RuntimeGuard';
        $this->version = $config['version'] ?? '3.0';
    }

    /**
     * Create from configuration.
     */
    public static function fromConfig(array $config, ?LoggerInterface $logger = null): self
    {
        return new self(array_merge($config, ['logger' => $logger]));
    }

    /**
     * Send event to SIEM.
     */
    public function send(GuardResultInterface $result, InspectionContext $context): bool
    {
        if ($result->passed()) {
            return true;
        }

        $formatted = $this->formatEvent($result, $context);

        if ($this->endpoint) {
            return $this->sendToEndpoint($formatted);
        }

        // Log locally if no endpoint configured
        $this->logger?->info('SIEM Event', ['event' => $formatted]);

        return true;
    }

    /**
     * Format event according to configured format.
     */
    public function formatEvent(GuardResultInterface $result, InspectionContext $context): string|array
    {
        return match ($this->format) {
            self::FORMAT_CEF => $this->formatCef($result, $context),
            self::FORMAT_LEEF => $this->formatLeef($result, $context),
            self::FORMAT_SPLUNK => $this->formatSplunk($result, $context),
            self::FORMAT_ELASTIC => $this->formatElastic($result, $context),
            default => $this->formatJson($result, $context),
        };
    }

    /**
     * Format as CEF (Common Event Format).
     *
     * CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
     */
    private function formatCef(GuardResultInterface $result, InspectionContext $context): string
    {
        $severity = $this->mapSeverityCef($result->getThreatLevel()->value);
        $signatureId = $this->generateSignatureId($result);

        $extension = [
            'src=' . ($context->ip() ?? 'unknown'),
            'suser=' . ($context->userId() ?? 'anonymous'),
            'request=' . ($context->path() ?? '/'),
            'requestMethod=' . ($context->method() ?? 'GET'),
            'msg=' . $this->escapeExtension($result->getMessage()),
            'cs1Label=GuardName',
            'cs1=' . $result->getGuardName(),
            'cs2Label=ThreatLevel',
            'cs2=' . $result->getThreatLevel()->value,
        ];

        return sprintf(
            'CEF:0|%s|%s|%s|%s|%s|%d|%s',
            $this->escapeCefHeader($this->vendor),
            $this->escapeCefHeader($this->product),
            $this->escapeCefHeader($this->version),
            $signatureId,
            $this->escapeCefHeader($result->getGuardName() . ' Detection'),
            $severity,
            implode(' ', $extension)
        );
    }

    /**
     * Format as LEEF (Log Event Extended Format).
     *
     * LEEF:Version|Vendor|Product|Version|EventID|Extension
     */
    private function formatLeef(GuardResultInterface $result, InspectionContext $context): string
    {
        $extension = [
            'src=' . ($context->ip() ?? 'unknown'),
            'usrName=' . ($context->userId() ?? 'anonymous'),
            'url=' . ($context->path() ?? '/'),
            'proto=HTTP',
            'sev=' . $this->mapSeverityLeef($result->getThreatLevel()->value),
            'cat=' . $result->getGuardName(),
            'msg=' . $this->escapeExtension($result->getMessage()),
        ];

        return sprintf(
            'LEEF:2.0|%s|%s|%s|%s|%s',
            $this->vendor,
            $this->product,
            $this->version,
            $this->generateSignatureId($result),
            implode("\t", $extension)
        );
    }

    /**
     * Format for Splunk HEC.
     */
    private function formatSplunk(GuardResultInterface $result, InspectionContext $context): array
    {
        return [
            'time' => time(),
            'host' => gethostname(),
            'source' => $this->product,
            'sourcetype' => 'runtime_guard:security',
            'event' => [
                'guard' => $result->getGuardName(),
                'threat_level' => $result->getThreatLevel()->value,
                'message' => $result->getMessage(),
                'src_ip' => $context->ip(),
                'user' => $context->userId(),
                'path' => $context->path(),
                'method' => $context->method(),
                'session_id' => $context->sessionId(),
                'metadata' => $result->getMetadata(),
            ],
        ];
    }

    /**
     * Format for Elastic Common Schema (ECS).
     */
    private function formatElastic(GuardResultInterface $result, InspectionContext $context): array
    {
        return [
            '@timestamp' => gmdate('Y-m-d\TH:i:s.v\Z'),
            'ecs' => ['version' => '8.0.0'],
            'event' => [
                'kind' => 'alert',
                'category' => ['intrusion_detection'],
                'type' => ['info'],
                'severity' => $this->mapSeverityElastic($result->getThreatLevel()->value),
                'risk_score' => $result->getThreatLevel()->weight(),
                'provider' => $this->product,
                'module' => $result->getGuardName(),
                'original' => $result->getMessage(),
            ],
            'source' => [
                'ip' => $context->ip(),
            ],
            'user' => [
                'id' => $context->userId(),
            ],
            'url' => [
                'path' => $context->path(),
            ],
            'http' => [
                'request' => [
                    'method' => $context->method(),
                ],
            ],
            'rule' => [
                'name' => $result->getGuardName(),
                'category' => 'security',
            ],
            'threat' => [
                'indicator' => [
                    'type' => $this->mapThreatType($result->getGuardName()),
                ],
            ],
            'labels' => [
                'guard' => $result->getGuardName(),
                'threat_level' => $result->getThreatLevel()->value,
            ],
        ];
    }

    /**
     * Format as generic JSON.
     */
    private function formatJson(GuardResultInterface $result, InspectionContext $context): array
    {
        return [
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            'vendor' => $this->vendor,
            'product' => $this->product,
            'version' => $this->version,
            'event' => [
                'guard' => $result->getGuardName(),
                'threat_level' => $result->getThreatLevel()->value,
                'severity_score' => $result->getThreatLevel()->weight(),
                'message' => $result->getMessage(),
                'metadata' => $result->getMetadata(),
            ],
            'context' => [
                'ip' => $context->ip(),
                'user_id' => $context->userId(),
                'session_id' => $context->sessionId(),
                'path' => $context->path(),
                'method' => $context->method(),
                'route' => $context->routeName(),
            ],
            'host' => gethostname(),
        ];
    }

    /**
     * Send to configured endpoint.
     */
    private function sendToEndpoint(string|array $event): bool
    {
        try {
            $payload = is_array($event) ? json_encode($event) : $event;

            $ch = curl_init($this->endpoint);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $payload,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 5,
                CURLOPT_HTTPHEADER => array_merge(
                    ['Content-Type: application/json'],
                    array_map(fn($k, $v) => "$k: $v", array_keys($this->headers), $this->headers)
                ),
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            return $httpCode >= 200 && $httpCode < 300;
        } catch (\Throwable $e) {
            $this->logger?->error('SIEM send failed', ['error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Generate signature ID from result.
     */
    private function generateSignatureId(GuardResultInterface $result): string
    {
        return 'RG-' . strtoupper(substr(md5($result->getGuardName()), 0, 8));
    }

    /**
     * Map threat level to CEF severity (0-10).
     */
    private function mapSeverityCef(string $level): int
    {
        return match ($level) {
            'critical' => 10,
            'high' => 7,
            'medium' => 4,
            'low' => 1,
            default => 0,
        };
    }

    /**
     * Map threat level to LEEF severity.
     */
    private function mapSeverityLeef(string $level): int
    {
        return match ($level) {
            'critical' => 9,
            'high' => 6,
            'medium' => 3,
            'low' => 1,
            default => 0,
        };
    }

    /**
     * Map threat level to Elastic severity.
     */
    private function mapSeverityElastic(string $level): int
    {
        return match ($level) {
            'critical' => 90,
            'high' => 73,
            'medium' => 47,
            'low' => 21,
            default => 0,
        };
    }

    /**
     * Map guard name to threat type.
     */
    private function mapThreatType(string $guardName): string
    {
        return match ($guardName) {
            'sql_injection', 'nosql_injection' => 'database-attack',
            'xss' => 'cross-site-scripting',
            'command_injection' => 'command-execution',
            'ssrf' => 'server-side-request-forgery',
            'credential_stuffing' => 'credential-access',
            default => 'unknown',
        };
    }

    /**
     * Escape CEF header value.
     */
    private function escapeCefHeader(string $value): string
    {
        return str_replace(['\\', '|'], ['\\\\', '\\|'], $value);
    }

    /**
     * Escape CEF extension value.
     */
    private function escapeExtension(string $value): string
    {
        return str_replace(['\\', '=', "\n", "\r"], ['\\\\', '\\=', '\\n', '\\r'], $value);
    }
}
