<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Advanced;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

/**
 * Honeytoken Manager.
 *
 * Manages decoy credentials and tokens to detect breaches:
 * - Token generation and deployment
 * - Access monitoring
 * - Breach detection
 * - Alert generation
 */
class HoneytokenManager
{
    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'token_types' => ['api_key', 'password', 'jwt', 'session', 'database'],
            'expiry_days' => 365,
            'alert_on_access' => true,
            'log_details' => true,
        ], $config);
    }

    /**
     * Generate a new honeytoken.
     */
    public function generate(string $type, array $options = []): Honeytoken
    {
        $token = new Honeytoken(
            id: 'ht_' . bin2hex(random_bytes(8)),
            type: $type,
            value: $this->generateValue($type, $options),
            name: $options['name'] ?? "Honeytoken-{$type}",
            description: $options['description'] ?? null,
            location: $options['location'] ?? null,
            createdAt: time(),
            expiresAt: time() + ($this->config['expiry_days'] * 86400),
            metadata: $options['metadata'] ?? []
        );

        $this->store($token);

        return $token;
    }

    /**
     * Generate multiple honeytokens.
     */
    public function generateSet(array $types, array $options = []): array
    {
        $tokens = [];

        foreach ($types as $type) {
            $tokens[] = $this->generate($type, $options);
        }

        return $tokens;
    }

    /**
     * Check if value is a honeytoken.
     */
    public function check(string $value): HoneytokenCheckResult
    {
        $hash = $this->hashValue($value);
        $tokenData = Cache::get("honeytoken:hash:{$hash}");

        if ($tokenData === null) {
            return new HoneytokenCheckResult(
                isHoneytoken: false,
                token: null,
                accessCount: 0
            );
        }

        // Record access
        $this->recordAccess($tokenData['id'], $value);

        $token = $this->get($tokenData['id']);

        return new HoneytokenCheckResult(
            isHoneytoken: true,
            token: $token,
            accessCount: $this->getAccessCount($tokenData['id'])
        );
    }

    /**
     * Record honeytoken access.
     */
    public function recordAccess(string $tokenId, string $value, array $context = []): void
    {
        $accessRecord = [
            'token_id' => $tokenId,
            'timestamp' => time(),
            'ip' => $context['ip'] ?? request()->ip(),
            'user_agent' => $context['user_agent'] ?? request()->userAgent(),
            'path' => $context['path'] ?? request()->path(),
            'method' => $context['method'] ?? request()->method(),
            'headers' => $context['headers'] ?? [],
        ];

        // Store access record
        $accessKey = "honeytoken:access:{$tokenId}";
        $accesses = Cache::get($accessKey, []);
        array_unshift($accesses, $accessRecord);
        Cache::put($accessKey, array_slice($accesses, 0, 100), 86400 * 30);

        // Increment counter
        Cache::increment("honeytoken:count:{$tokenId}");

        // Generate alert
        if ($this->config['alert_on_access']) {
            $this->generateAlert($tokenId, $accessRecord);
        }
    }

    /**
     * Get honeytoken by ID.
     */
    public function get(string $id): ?Honeytoken
    {
        $data = Cache::get("honeytoken:{$id}");

        if ($data === null) {
            return null;
        }

        return Honeytoken::fromArray($data);
    }

    /**
     * Get all honeytokens.
     */
    public function getAll(): array
    {
        $index = Cache::get('honeytoken:index', []);
        $tokens = [];

        foreach ($index as $id) {
            $token = $this->get($id);
            if ($token !== null) {
                $tokens[] = $token;
            }
        }

        return $tokens;
    }

    /**
     * Get access records for token.
     */
    public function getAccessRecords(string $tokenId): array
    {
        return Cache::get("honeytoken:access:{$tokenId}", []);
    }

    /**
     * Get access count for token.
     */
    public function getAccessCount(string $tokenId): int
    {
        return (int) Cache::get("honeytoken:count:{$tokenId}", 0);
    }

    /**
     * Revoke honeytoken.
     */
    public function revoke(string $id): bool
    {
        $token = $this->get($id);
        if ($token === null) {
            return false;
        }

        // Remove from hash index
        $hash = $this->hashValue($token->value);
        Cache::forget("honeytoken:hash:{$hash}");

        // Mark as revoked
        $data = $token->toArray();
        $data['revoked'] = true;
        $data['revoked_at'] = time();
        Cache::put("honeytoken:{$id}", $data, 86400 * 30);

        return true;
    }

    /**
     * Get breach indicators.
     */
    public function getBreachIndicators(): array
    {
        $tokens = $this->getAll();
        $indicators = [];

        foreach ($tokens as $token) {
            $accessCount = $this->getAccessCount($token->id);
            if ($accessCount > 0) {
                $accesses = $this->getAccessRecords($token->id);
                $indicators[] = [
                    'token' => $token,
                    'access_count' => $accessCount,
                    'first_access' => end($accesses),
                    'last_access' => reset($accesses),
                    'unique_ips' => count(array_unique(array_column($accesses, 'ip'))),
                    'severity' => $this->assessSeverity($token, $accesses),
                ];
            }
        }

        return $indicators;
    }

    /**
     * Generate deployment suggestions.
     */
    public function getDeploymentSuggestions(): array
    {
        return [
            [
                'type' => 'api_key',
                'location' => 'Environment variables (.env)',
                'description' => 'Deploy as a fake API key that looks legitimate',
                'example' => 'PAYMENT_API_KEY=ht_xxx',
            ],
            [
                'type' => 'password',
                'location' => 'Database seed files',
                'description' => 'Add as test user credentials',
                'example' => 'admin@test.com / honeytoken_password',
            ],
            [
                'type' => 'jwt',
                'location' => 'Comments or documentation',
                'description' => 'Leave as example token in docs',
                'example' => 'Authorization: Bearer ht_jwt_xxx',
            ],
            [
                'type' => 'database',
                'location' => 'Config files',
                'description' => 'Fake database connection string',
                'example' => 'DB_PASSWORD=ht_db_xxx',
            ],
            [
                'type' => 'session',
                'location' => 'Log files (intentionally)',
                'description' => 'Session token in fake logs',
                'example' => 'Session: ht_session_xxx',
            ],
        ];
    }

    /**
     * Store honeytoken.
     */
    private function store(Honeytoken $token): void
    {
        // Store token data
        Cache::put("honeytoken:{$token->id}", $token->toArray(), $token->expiresAt - time());

        // Store hash mapping
        $hash = $this->hashValue($token->value);
        Cache::put("honeytoken:hash:{$hash}", ['id' => $token->id], $token->expiresAt - time());

        // Update index
        $index = Cache::get('honeytoken:index', []);
        $index[] = $token->id;
        Cache::put('honeytoken:index', array_unique($index), 86400 * 365);
    }

    /**
     * Generate token value based on type.
     */
    private function generateValue(string $type, array $options = []): string
    {
        return match ($type) {
            'api_key' => $this->generateApiKey($options),
            'password' => $this->generatePassword($options),
            'jwt' => $this->generateJwt($options),
            'session' => $this->generateSession($options),
            'database' => $this->generateDatabaseCred($options),
            default => 'ht_' . bin2hex(random_bytes(16)),
        };
    }

    /**
     * Generate fake API key.
     */
    private function generateApiKey(array $options): string
    {
        $prefix = $options['prefix'] ?? 'sk_live_';
        return $prefix . bin2hex(random_bytes(24));
    }

    /**
     * Generate fake password.
     */
    private function generatePassword(array $options): string
    {
        $length = $options['length'] ?? 16;
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%';
        $password = '';
        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, strlen($chars) - 1)];
        }
        return $password;
    }

    /**
     * Generate fake JWT.
     */
    private function generateJwt(array $options): string
    {
        $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode([
            'sub' => 'honeytoken',
            'iat' => time(),
            'exp' => time() + 86400,
        ]));
        $signature = base64_encode(bin2hex(random_bytes(32)));

        return "{$header}.{$payload}.{$signature}";
    }

    /**
     * Generate fake session token.
     */
    private function generateSession(array $options): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Generate fake database credential.
     */
    private function generateDatabaseCred(array $options): string
    {
        return Str::random(24);
    }

    /**
     * Hash token value for lookup.
     */
    private function hashValue(string $value): string
    {
        return hash('sha256', $value);
    }

    /**
     * Generate alert for honeytoken access.
     */
    private function generateAlert(string $tokenId, array $accessRecord): void
    {
        $alert = [
            'type' => 'honeytoken_accessed',
            'severity' => 'critical',
            'token_id' => $tokenId,
            'access' => $accessRecord,
            'timestamp' => time(),
        ];

        // Store alert
        $alerts = Cache::get('honeytoken:alerts', []);
        array_unshift($alerts, $alert);
        Cache::put('honeytoken:alerts', array_slice($alerts, 0, 100), 86400 * 7);

        // Could also trigger webhooks, emails, etc.
    }

    /**
     * Assess breach severity.
     */
    private function assessSeverity(Honeytoken $token, array $accesses): string
    {
        $count = count($accesses);
        $uniqueIps = count(array_unique(array_column($accesses, 'ip')));

        if ($count >= 10 || $uniqueIps >= 5) {
            return 'critical';
        } elseif ($count >= 5 || $uniqueIps >= 3) {
            return 'high';
        } elseif ($count >= 2) {
            return 'medium';
        }

        return 'low';
    }
}

/**
 * Honeytoken.
 */
class Honeytoken
{
    public function __construct(
        public readonly string $id,
        public readonly string $type,
        public readonly string $value,
        public readonly string $name,
        public readonly ?string $description,
        public readonly ?string $location,
        public readonly int $createdAt,
        public readonly int $expiresAt,
        public readonly array $metadata = []
    ) {}

    public function isExpired(): bool
    {
        return time() > $this->expiresAt;
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'type' => $this->type,
            'value' => $this->value,
            'name' => $this->name,
            'description' => $this->description,
            'location' => $this->location,
            'created_at' => $this->createdAt,
            'expires_at' => $this->expiresAt,
            'metadata' => $this->metadata,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            $data['id'],
            $data['type'],
            $data['value'],
            $data['name'],
            $data['description'] ?? null,
            $data['location'] ?? null,
            $data['created_at'],
            $data['expires_at'],
            $data['metadata'] ?? []
        );
    }
}

/**
 * Honeytoken Check Result.
 */
class HoneytokenCheckResult
{
    public function __construct(
        public readonly bool $isHoneytoken,
        public readonly ?Honeytoken $token,
        public readonly int $accessCount
    ) {}
}
