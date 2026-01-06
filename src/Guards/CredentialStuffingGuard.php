<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\ContextAwareGuard;
use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;
use M9nx\RuntimeGuard\Support\GuardResult;
use M9nx\RuntimeGuard\Support\InspectionContext;
use Psr\SimpleCache\CacheInterface;
use Illuminate\Support\Facades\Http;

/**
 * Detects credential stuffing and distributed brute-force attacks.
 *
 * Features:
 * - Velocity analysis for failed authentication attempts
 * - IP-based and user-based tracking
 * - Optional Have I Been Pwned integration (k-anonymity)
 * - Distributed attack pattern detection
 */
class CredentialStuffingGuard extends AbstractGuard implements ContextAwareGuard
{
    protected string $name = 'credential_stuffing';
    protected ThreatLevel $defaultThreatLevel = ThreatLevel::HIGH;

    private ?CacheInterface $cache;
    private string $cachePrefix = 'runtime_guard:stuffing:';

    // Velocity thresholds
    private int $maxFailedAttemptsPerIp;
    private int $maxFailedAttemptsPerUser;
    private int $windowSeconds;
    private int $distributedThreshold;
    private int $distributedWindowSeconds;

    // HIBP integration
    private bool $breachCheckEnabled;
    private string $hibpApiUrl = 'https://api.pwnedpasswords.com/range/';

    public function __construct(array $config = [])
    {
        parent::__construct($config);

        $this->cache = $config['cache'] ?? null;
        $this->maxFailedAttemptsPerIp = $config['max_failed_per_ip'] ?? 10;
        $this->maxFailedAttemptsPerUser = $config['max_failed_per_user'] ?? 5;
        $this->windowSeconds = $config['window_seconds'] ?? 300;
        $this->distributedThreshold = $config['distributed_threshold'] ?? 50;
        $this->distributedWindowSeconds = $config['distributed_window_seconds'] ?? 60;
        $this->breachCheckEnabled = $config['breach_check_enabled'] ?? false;
    }

    /**
     * Check if this guard applies to the current context.
     */
    public function appliesTo(InspectionContext $context): bool
    {
        $route = $context->routeName() ?? '';
        $path = $context->path() ?? '';

        // Apply to authentication-related routes
        $authPatterns = [
            'login', 'signin', 'authenticate', 'auth',
            'password', 'reset', 'forgot', 'register',
        ];

        foreach ($authPatterns as $pattern) {
            if (stripos($route, $pattern) !== false || stripos($path, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Quick scan for obvious stuffing indicators.
     */
    public function quickScan(mixed $input, InspectionContext $context): ?GuardResultInterface
    {
        if (!$this->cache) {
            return null;
        }

        $ip = $context->ip();
        if (!$ip) {
            return null;
        }

        // Check if IP is already flagged
        $ipKey = $this->cachePrefix . 'flagged:ip:' . md5($ip);
        if ($this->cache->get($ipKey)) {
            return GuardResult::threat(
                $this->name,
                ThreatLevel::HIGH,
                'IP flagged for credential stuffing',
                ['ip' => $this->maskIp($ip)]
            );
        }

        return null;
    }

    /**
     * Deep inspection for credential stuffing patterns.
     */
    public function deepInspection(mixed $input, InspectionContext $context): GuardResultInterface
    {
        $threats = [];
        $ip = $context->ip();
        $inputArray = $this->normalizeInput($input);

        // Extract potential username/email from input
        $identifier = $this->extractIdentifier($inputArray);
        $password = $this->extractPassword($inputArray);

        // Check IP velocity
        if ($ip && $this->cache) {
            $ipVelocity = $this->checkIpVelocity($ip);
            if ($ipVelocity['exceeded']) {
                $threats[] = [
                    'type' => 'ip_velocity_exceeded',
                    'attempts' => $ipVelocity['count'],
                    'threshold' => $this->maxFailedAttemptsPerIp,
                    'ip' => $this->maskIp($ip),
                ];
            }
        }

        // Check user velocity
        if ($identifier && $this->cache) {
            $userVelocity = $this->checkUserVelocity($identifier);
            if ($userVelocity['exceeded']) {
                $threats[] = [
                    'type' => 'user_velocity_exceeded',
                    'attempts' => $userVelocity['count'],
                    'threshold' => $this->maxFailedAttemptsPerUser,
                    'identifier' => $this->maskIdentifier($identifier),
                ];
            }
        }

        // Check for distributed attack patterns
        if ($this->cache) {
            $distributed = $this->checkDistributedPattern();
            if ($distributed['detected']) {
                $threats[] = [
                    'type' => 'distributed_attack_detected',
                    'unique_ips' => $distributed['unique_ips'],
                    'total_attempts' => $distributed['total_attempts'],
                ];
            }
        }

        // Check password against breach database
        if ($password && $this->breachCheckEnabled) {
            $breach = $this->checkPasswordBreach($password);
            if ($breach['found']) {
                $threats[] = [
                    'type' => 'breached_password',
                    'occurrences' => $breach['count'],
                    'recommendation' => 'Password found in known data breaches',
                ];
            }
        }

        if (!empty($threats)) {
            return GuardResult::fail(
                $this->name,
                ThreatLevel::HIGH,
                'Credential stuffing pattern detected',
                [
                    'threats' => $threats,
                    'ip' => $ip ? $this->maskIp($ip) : null,
                ]
            );
        }

        return GuardResult::pass($this->name, 'No credential stuffing detected');
    }

    /**
     * Record a failed authentication attempt.
     */
    public function recordFailedAttempt(string $ip, ?string $identifier = null): void
    {
        if (!$this->cache) {
            return;
        }

        $now = time();

        // Record IP attempt
        $ipKey = $this->cachePrefix . 'attempts:ip:' . md5($ip);
        $ipAttempts = $this->cache->get($ipKey, []);
        $ipAttempts[] = $now;
        $ipAttempts = $this->pruneOldAttempts($ipAttempts, $this->windowSeconds);
        $this->cache->set($ipKey, $ipAttempts, $this->windowSeconds);

        // Flag IP if threshold exceeded
        if (count($ipAttempts) >= $this->maxFailedAttemptsPerIp) {
            $this->cache->set(
                $this->cachePrefix . 'flagged:ip:' . md5($ip),
                true,
                $this->windowSeconds
            );
        }

        // Record user attempt
        if ($identifier) {
            $userKey = $this->cachePrefix . 'attempts:user:' . md5($identifier);
            $userAttempts = $this->cache->get($userKey, []);
            $userAttempts[] = $now;
            $userAttempts = $this->pruneOldAttempts($userAttempts, $this->windowSeconds);
            $this->cache->set($userKey, $userAttempts, $this->windowSeconds);
        }

        // Record for distributed detection
        $globalKey = $this->cachePrefix . 'global:attempts';
        $globalAttempts = $this->cache->get($globalKey, []);
        $globalAttempts[] = ['ip' => md5($ip), 'time' => $now];
        $globalAttempts = array_filter(
            $globalAttempts,
            fn($a) => $a['time'] > $now - $this->distributedWindowSeconds
        );
        $this->cache->set($globalKey, array_values($globalAttempts), $this->distributedWindowSeconds);
    }

    /**
     * Record a successful authentication (resets counters).
     */
    public function recordSuccessfulAttempt(string $ip, ?string $identifier = null): void
    {
        if (!$this->cache) {
            return;
        }

        // Clear IP flag
        $this->cache->delete($this->cachePrefix . 'flagged:ip:' . md5($ip));

        // Reduce IP attempts
        $ipKey = $this->cachePrefix . 'attempts:ip:' . md5($ip);
        $this->cache->delete($ipKey);

        // Clear user attempts
        if ($identifier) {
            $this->cache->delete($this->cachePrefix . 'attempts:user:' . md5($identifier));
        }
    }

    /**
     * Check IP velocity.
     */
    private function checkIpVelocity(string $ip): array
    {
        $ipKey = $this->cachePrefix . 'attempts:ip:' . md5($ip);
        $attempts = $this->cache->get($ipKey, []);
        $attempts = $this->pruneOldAttempts($attempts, $this->windowSeconds);

        return [
            'exceeded' => count($attempts) >= $this->maxFailedAttemptsPerIp,
            'count' => count($attempts),
        ];
    }

    /**
     * Check user velocity.
     */
    private function checkUserVelocity(string $identifier): array
    {
        $userKey = $this->cachePrefix . 'attempts:user:' . md5($identifier);
        $attempts = $this->cache->get($userKey, []);
        $attempts = $this->pruneOldAttempts($attempts, $this->windowSeconds);

        return [
            'exceeded' => count($attempts) >= $this->maxFailedAttemptsPerUser,
            'count' => count($attempts),
        ];
    }

    /**
     * Check for distributed attack pattern.
     */
    private function checkDistributedPattern(): array
    {
        $globalKey = $this->cachePrefix . 'global:attempts';
        $attempts = $this->cache->get($globalKey, []);

        $uniqueIps = count(array_unique(array_column($attempts, 'ip')));
        $totalAttempts = count($attempts);

        return [
            'detected' => $totalAttempts >= $this->distributedThreshold && $uniqueIps >= 10,
            'unique_ips' => $uniqueIps,
            'total_attempts' => $totalAttempts,
        ];
    }

    /**
     * Check password against Have I Been Pwned using k-anonymity.
     */
    private function checkPasswordBreach(string $password): array
    {
        try {
            $sha1 = strtoupper(sha1($password));
            $prefix = substr($sha1, 0, 5);
            $suffix = substr($sha1, 5);

            $response = Http::timeout(2)->get($this->hibpApiUrl . $prefix);

            if ($response->successful()) {
                $hashes = explode("\n", $response->body());

                foreach ($hashes as $hash) {
                    [$hashSuffix, $count] = explode(':', trim($hash));
                    if (strtoupper($hashSuffix) === $suffix) {
                        return ['found' => true, 'count' => (int) $count];
                    }
                }
            }
        } catch (\Throwable) {
            // Fail open - don't block on API errors
        }

        return ['found' => false, 'count' => 0];
    }

    /**
     * Extract identifier (username/email) from input.
     */
    private function extractIdentifier(array $input): ?string
    {
        $identifierFields = ['email', 'username', 'login', 'user', 'identity'];

        foreach ($identifierFields as $field) {
            if (isset($input[$field]) && is_string($input[$field])) {
                return $input[$field];
            }
        }

        return null;
    }

    /**
     * Extract password from input.
     */
    private function extractPassword(array $input): ?string
    {
        $passwordFields = ['password', 'pass', 'passwd', 'pwd'];

        foreach ($passwordFields as $field) {
            if (isset($input[$field]) && is_string($input[$field])) {
                return $input[$field];
            }
        }

        return null;
    }

    /**
     * Prune attempts older than window.
     */
    private function pruneOldAttempts(array $attempts, int $windowSeconds): array
    {
        $cutoff = time() - $windowSeconds;
        return array_values(array_filter($attempts, fn($t) => $t > $cutoff));
    }

    /**
     * Mask IP for logging.
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
     * Mask identifier for logging.
     */
    private function maskIdentifier(string $identifier): string
    {
        if (str_contains($identifier, '@')) {
            [$local, $domain] = explode('@', $identifier, 2);
            return substr($local, 0, 2) . '***@' . $domain;
        }

        return substr($identifier, 0, 2) . '***';
    }

    /**
     * Normalize input to array.
     */
    private function normalizeInput(mixed $input): array
    {
        if (is_array($input)) {
            return $input;
        }

        if (is_object($input)) {
            return (array) $input;
        }

        return [];
    }

    /**
     * Get current statistics.
     */
    public function getStats(): array
    {
        if (!$this->cache) {
            return ['cache' => 'disabled'];
        }

        $globalKey = $this->cachePrefix . 'global:attempts';
        $attempts = $this->cache->get($globalKey, []);

        return [
            'global_attempts' => count($attempts),
            'unique_ips' => count(array_unique(array_column($attempts, 'ip'))),
            'window_seconds' => $this->distributedWindowSeconds,
        ];
    }
}
