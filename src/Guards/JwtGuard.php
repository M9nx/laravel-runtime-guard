<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardInterface;
use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;
use M9nx\RuntimeGuard\Support\GuardResult;
use Illuminate\Http\Request;

/**
 * JWT/Token Abuse Guard.
 *
 * Detects common JWT attacks:
 * - Algorithm confusion (none, HS256 vs RS256)
 * - Token replay attacks
 * - Expired/future token manipulation
 * - JKU/X5U injection
 * - Key ID manipulation
 */
class JwtGuard implements GuardInterface
{
    private bool $enabled;
    private array $allowedAlgorithms;
    private bool $rejectNoneAlgorithm;
    private bool $rejectSymmetricWithPublicKey;
    private bool $detectReplay;
    private int $tokenReplayWindow;
    private int $maxClockSkew;
    private bool $detectJkuInjection;
    private ?object $cache;
    private array $trustedIssuers;

    public function __construct(array $config = [])
    {
        $this->enabled = $config['enabled'] ?? true;
        $this->allowedAlgorithms = $config['allowed_algorithms'] ?? ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];
        $this->rejectNoneAlgorithm = $config['reject_none_algorithm'] ?? true;
        $this->rejectSymmetricWithPublicKey = $config['reject_symmetric_with_public_key'] ?? true;
        $this->detectReplay = $config['detect_replay'] ?? true;
        $this->tokenReplayWindow = $config['token_replay_window'] ?? 300; // 5 minutes
        $this->maxClockSkew = $config['max_clock_skew'] ?? 60; // 1 minute
        $this->detectJkuInjection = $config['detect_jku_injection'] ?? true;
        $this->cache = $config['cache'] ?? null;
        $this->trustedIssuers = $config['trusted_issuers'] ?? [];
    }

    public function inspect(mixed $input, array $context = []): GuardResultInterface
    {
        if (!$this->enabled) {
            return GuardResult::pass($this->getName());
        }

        // Get request from context or try to resolve it
        $request = $context['request'] ?? ($input instanceof Request ? $input : app('request'));
        
        $threats = [];
        $metadata = [];

        // Extract JWT from various locations
        $tokens = $this->extractTokens($request);

        if (empty($tokens)) {
            return new GuardResult(
                guardName: $this->getName(),
                passed: true,
                message: 'No JWT tokens found',
                metadata: ['tokens_found' => 0]
            );
        }

        $metadata['tokens_found'] = count($tokens);

        foreach ($tokens as $location => $token) {
            $tokenThreats = $this->analyzeToken($token, $location);
            $threats = array_merge($threats, $tokenThreats);
        }

        if (!empty($threats)) {
            $highestSeverity = $this->getHighestSeverity($threats);
            return GuardResult::fail(
                $this->getName(),
                $highestSeverity,
                'JWT security threats detected',
                ['threats' => $threats, ...$metadata]
            );
        }

        return new GuardResult(
            guardName: $this->getName(),
            passed: true,
            message: 'No threat detected',
            metadata: $metadata
        );
    }

    /**
     * Determine the highest severity from threats.
     */
    private function getHighestSeverity(array $threats): ThreatLevel
    {
        $severityOrder = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        $highest = 0;

        foreach ($threats as $threat) {
            $severity = $threat['severity'] ?? 'low';
            $highest = max($highest, $severityOrder[$severity] ?? 1);
        }

        return match ($highest) {
            4 => ThreatLevel::CRITICAL,
            3 => ThreatLevel::HIGH,
            2 => ThreatLevel::MEDIUM,
            default => ThreatLevel::LOW,
        };
    }

    /**
     * Extract JWT tokens from request.
     */
    private function extractTokens(object $request): array
    {
        $tokens = [];

        // Authorization header
        $authHeader = $request->header('Authorization');
        if ($authHeader && preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
            $tokens['authorization_header'] = $matches[1];
        }

        // X-Access-Token header
        $accessToken = $request->header('X-Access-Token');
        if ($accessToken) {
            $tokens['x_access_token'] = $accessToken;
        }

        // Query parameter
        $queryToken = $request->query('token') ?? $request->query('access_token');
        if ($queryToken) {
            $tokens['query_parameter'] = $queryToken;
        }

        // Cookie
        $cookieToken = $request->cookie('token') ?? $request->cookie('jwt');
        if ($cookieToken) {
            $tokens['cookie'] = $cookieToken;
        }

        return $tokens;
    }

    /**
     * Analyze a JWT token for threats.
     */
    private function analyzeToken(string $token, string $location): array
    {
        $threats = [];

        // Basic structure validation
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            // Not a JWT, skip
            return [];
        }

        // Decode header
        $header = $this->decodeBase64Url($parts[0]);
        if (!$header) {
            return []; // Invalid base64, not a JWT
        }

        $headerData = json_decode($header, true);
        if (!$headerData) {
            return [];
        }

        // Check algorithm
        $algorithm = $headerData['alg'] ?? 'none';

        // Threat 1: None algorithm attack
        if ($this->rejectNoneAlgorithm && strtolower($algorithm) === 'none') {
            $threats[] = [
                'type' => 'jwt_none_algorithm',
                'severity' => 'critical',
                'message' => 'JWT uses "none" algorithm - potential algorithm confusion attack',
                'location' => $location,
                'details' => ['algorithm' => $algorithm],
            ];
        }

        // Threat 2: Algorithm not in whitelist
        if (!empty($this->allowedAlgorithms) && !in_array($algorithm, $this->allowedAlgorithms)) {
            $threats[] = [
                'type' => 'jwt_disallowed_algorithm',
                'severity' => 'high',
                'message' => "JWT uses disallowed algorithm: {$algorithm}",
                'location' => $location,
                'details' => [
                    'algorithm' => $algorithm,
                    'allowed' => $this->allowedAlgorithms,
                ],
            ];
        }

        // Threat 3: Symmetric algorithm with RS/ES (algorithm confusion)
        if ($this->rejectSymmetricWithPublicKey) {
            if (in_array($algorithm, ['HS256', 'HS384', 'HS512'])) {
                if (!empty($this->allowedAlgorithms) && 
                    (in_array('RS256', $this->allowedAlgorithms) || in_array('ES256', $this->allowedAlgorithms))) {
                    $threats[] = [
                        'type' => 'jwt_algorithm_confusion',
                        'severity' => 'critical',
                        'message' => 'Symmetric algorithm used where asymmetric expected - potential key confusion attack',
                        'location' => $location,
                        'details' => ['algorithm' => $algorithm],
                    ];
                }
            }
        }

        // Threat 4: JKU/X5U injection
        if ($this->detectJkuInjection) {
            $jku = $headerData['jku'] ?? null;
            $x5u = $headerData['x5u'] ?? null;

            if ($jku && $this->isSuspiciousUrl($jku)) {
                $threats[] = [
                    'type' => 'jwt_jku_injection',
                    'severity' => 'critical',
                    'message' => 'Suspicious JKU URL detected - potential key injection attack',
                    'location' => $location,
                    'details' => ['jku' => $jku],
                ];
            }

            if ($x5u && $this->isSuspiciousUrl($x5u)) {
                $threats[] = [
                    'type' => 'jwt_x5u_injection',
                    'severity' => 'critical',
                    'message' => 'Suspicious X5U URL detected - potential key injection attack',
                    'location' => $location,
                    'details' => ['x5u' => $x5u],
                ];
            }
        }

        // Decode payload
        $payload = $this->decodeBase64Url($parts[1]);
        if ($payload) {
            $payloadData = json_decode($payload, true);
            if ($payloadData) {
                $payloadThreats = $this->analyzePayload($payloadData, $location, $token);
                $threats = array_merge($threats, $payloadThreats);
            }
        }

        return $threats;
    }

    /**
     * Analyze JWT payload.
     */
    private function analyzePayload(array $payload, string $location, string $token): array
    {
        $threats = [];
        $now = time();

        // Threat 5: Expired token manipulation (exp way in the past but still being used)
        $exp = $payload['exp'] ?? null;
        if ($exp !== null) {
            if ($exp < $now - $this->maxClockSkew) {
                // Token is expired - this might be fine, but let's note it
                $expiredFor = $now - $exp;
                if ($expiredFor > 86400) { // More than 1 day
                    $threats[] = [
                        'type' => 'jwt_expired_token',
                        'severity' => 'medium',
                        'message' => "JWT expired " . round($expiredFor / 3600) . " hours ago",
                        'location' => $location,
                        'details' => ['expired_at' => $exp, 'expired_for_seconds' => $expiredFor],
                    ];
                }
            }
        }

        // Threat 6: Future token (nbf in the future)
        $nbf = $payload['nbf'] ?? null;
        if ($nbf !== null && $nbf > $now + $this->maxClockSkew) {
            $threats[] = [
                'type' => 'jwt_future_token',
                'severity' => 'medium',
                'message' => 'JWT not valid yet (nbf in future)',
                'location' => $location,
                'details' => ['not_before' => $nbf],
            ];
        }

        // Threat 7: iat in the future
        $iat = $payload['iat'] ?? null;
        if ($iat !== null && $iat > $now + $this->maxClockSkew) {
            $threats[] = [
                'type' => 'jwt_future_issued',
                'severity' => 'medium',
                'message' => 'JWT issued in the future (iat in future)',
                'location' => $location,
                'details' => ['issued_at' => $iat],
            ];
        }

        // Threat 8: Untrusted issuer
        $iss = $payload['iss'] ?? null;
        if ($iss !== null && !empty($this->trustedIssuers) && !in_array($iss, $this->trustedIssuers)) {
            $threats[] = [
                'type' => 'jwt_untrusted_issuer',
                'severity' => 'high',
                'message' => "JWT from untrusted issuer: {$iss}",
                'location' => $location,
                'details' => ['issuer' => $iss, 'trusted' => $this->trustedIssuers],
            ];
        }

        // Threat 9: Token replay
        if ($this->detectReplay) {
            $jti = $payload['jti'] ?? null;
            if ($jti && $this->isReplayedToken($jti)) {
                $threats[] = [
                    'type' => 'jwt_replay',
                    'severity' => 'high',
                    'message' => 'JWT replay detected - token already used',
                    'location' => $location,
                    'details' => ['jti' => $jti],
                ];
            } elseif ($jti) {
                $this->recordTokenUse($jti);
            }
        }

        return $threats;
    }

    /**
     * Check if URL is suspicious.
     */
    private function isSuspiciousUrl(string $url): bool
    {
        // Check for localhost, private IPs, etc.
        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['host'])) {
            return true;
        }

        $host = strtolower($parsed['host']);

        // Suspicious patterns
        $suspiciousPatterns = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '::1',
            '10.',
            '172.16.',
            '172.17.',
            '172.18.',
            '172.19.',
            '172.20.',
            '172.21.',
            '172.22.',
            '172.23.',
            '172.24.',
            '172.25.',
            '172.26.',
            '172.27.',
            '172.28.',
            '172.29.',
            '172.30.',
            '172.31.',
            '192.168.',
            'attacker',
            'evil',
            'ngrok',
            'requestbin',
            'burpcollaborator',
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (str_contains($host, $pattern)) {
                return true;
            }
        }

        // Check for IP address (might be attempting to bypass domain checks)
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return true;
        }

        return false;
    }

    /**
     * Decode base64url.
     */
    private function decodeBase64Url(string $data): ?string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        return $decoded !== false ? $decoded : null;
    }

    /**
     * Check if token has been replayed.
     */
    private function isReplayedToken(string $jti): bool
    {
        if (!$this->cache) {
            return false;
        }

        $key = "jwt_jti:{$jti}";

        return $this->cache->has($key);
    }

    /**
     * Record token use for replay detection.
     */
    private function recordTokenUse(string $jti): void
    {
        if (!$this->cache) {
            return;
        }

        $key = "jwt_jti:{$jti}";
        $this->cache->put($key, time(), $this->tokenReplayWindow);
    }

    public function getName(): string
    {
        return 'jwt';
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getPriority(): int
    {
        return 50;
    }

    public function getSeverity(): string
    {
        return 'high';
    }
}
