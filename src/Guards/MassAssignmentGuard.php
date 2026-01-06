<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Guards;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Detects Mass Assignment attacks.
 *
 * Catches attempts to set dangerous fields that should not be
 * user-controllable (is_admin, role, password, etc).
 */
class MassAssignmentGuard extends AbstractGuard
{
    /**
     * Dangerous field names that should never come from user input.
     */
    protected array $dangerousFields = [
        // Auth/Role fields
        'is_admin',
        'is_superadmin',
        'is_super_admin',
        'admin',
        'role',
        'role_id',
        'roles',
        'permissions',
        'permission_ids',
        'is_moderator',
        'is_staff',
        'user_type',
        'account_type',
        'privilege',
        'privileges',
        'access_level',

        // Verification fields
        'email_verified',
        'email_verified_at',
        'phone_verified',
        'phone_verified_at',
        'verified',
        'verified_at',
        'is_verified',
        'is_active',
        'is_banned',
        'is_suspended',
        'status',

        // Security fields
        'password',
        'password_hash',
        'remember_token',
        'api_token',
        'api_key',
        'secret',
        'secret_key',
        'two_factor_secret',
        '2fa_secret',
        'recovery_codes',

        // Payment/Financial
        'balance',
        'credits',
        'wallet_balance',
        'subscription_ends_at',
        'plan_id',
        'is_premium',
        'is_paid',
        'stripe_id',
        'pm_type',
        'pm_last_four',
        'trial_ends_at',

        // System fields
        'id',
        'uuid',
        'created_at',
        'updated_at',
        'deleted_at',
        'created_by',
        'updated_by',
    ];

    /**
     * Context-specific dangerous patterns.
     */
    protected array $contextPatterns = [
        '*_id' => ['user_id', 'owner_id', 'author_id', 'created_by_id'],
        '*_token' => ['*_token'],
        '*_key' => ['*_key', '*_secret'],
        '*_secret' => ['*_secret'],
        '*_hash' => ['*_hash'],
    ];

    public function getName(): string
    {
        return 'mass-assignment';
    }

    protected function onBoot(): void
    {
        $this->dangerousFields = array_merge(
            $this->dangerousFields,
            $this->getConfig('dangerous_fields', [])
        );
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        if (!is_array($input)) {
            return $this->pass();
        }

        $detectedFields = $this->findDangerousFields($input);

        if (empty($detectedFields)) {
            return $this->pass();
        }

        // Determine threat level based on fields
        $level = $this->assessThreatLevel($detectedFields);

        return $this->threat(
            'Mass assignment attempt detected',
            $level,
            [
                'dangerous_fields' => $detectedFields,
                'field_count' => count($detectedFields),
            ]
        );
    }

    /**
     * Find dangerous fields in input.
     */
    protected function findDangerousFields(array $input, string $prefix = ''): array
    {
        $found = [];

        foreach ($input as $key => $value) {
            $fullKey = $prefix ? "{$prefix}.{$key}" : $key;
            $normalizedKey = strtolower((string) $key);

            // Direct match
            if (in_array($normalizedKey, array_map('strtolower', $this->dangerousFields), true)) {
                $found[] = [
                    'field' => $fullKey,
                    'value_type' => gettype($value),
                    'match_type' => 'exact',
                ];
                continue;
            }

            // Pattern match
            foreach ($this->contextPatterns as $pattern => $examples) {
                if ($this->matchesPattern($normalizedKey, $pattern)) {
                    $found[] = [
                        'field' => $fullKey,
                        'value_type' => gettype($value),
                        'match_type' => 'pattern',
                        'pattern' => $pattern,
                    ];
                    break;
                }
            }

            // Recurse into nested arrays
            if (is_array($value)) {
                $found = array_merge($found, $this->findDangerousFields($value, $fullKey));
            }
        }

        return $found;
    }

    /**
     * Match field name against pattern.
     */
    protected function matchesPattern(string $field, string $pattern): bool
    {
        // Convert glob pattern to regex
        $regex = '/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/i';
        return (bool) preg_match($regex, $field);
    }

    /**
     * Assess threat level based on detected fields.
     */
    protected function assessThreatLevel(array $detectedFields): ThreatLevel
    {
        $criticalFields = ['is_admin', 'role', 'permissions', 'password', 'api_token', 'api_key'];
        $highFields = ['email_verified_at', 'is_verified', 'balance', 'credits', 'id'];

        foreach ($detectedFields as $field) {
            $fieldName = strtolower(basename($field['field']));

            if (in_array($fieldName, $criticalFields, true)) {
                return ThreatLevel::CRITICAL;
            }

            if (in_array($fieldName, $highFields, true)) {
                return ThreatLevel::HIGH;
            }
        }

        return ThreatLevel::MEDIUM;
    }
}
