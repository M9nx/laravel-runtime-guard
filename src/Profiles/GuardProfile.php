<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Profiles;

use Mounir\RuntimeGuard\Contracts\ResponseMode;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Represents a guard configuration profile.
 *
 * Profiles define which guards to run and how to respond for specific contexts.
 */
final readonly class GuardProfile
{
    /**
     * @param  array<string>  $guards
     */
    public function __construct(
        public string $name,
        public array $guards = [],
        public ResponseMode $mode = ResponseMode::LOG,
        public ThreatLevel $threshold = ThreatLevel::HIGH,
        public bool $enabled = true,
    ) {}

    /**
     * Create from configuration array.
     */
    public static function fromConfig(string $name, array $config): self
    {
        return new self(
            name: $name,
            guards: $config['guards'] ?? [],
            mode: ResponseMode::tryFrom($config['mode'] ?? 'log') ?? ResponseMode::LOG,
            threshold: ThreatLevel::tryFrom($config['threshold'] ?? 'high') ?? ThreatLevel::HIGH,
            enabled: $config['enabled'] ?? true,
        );
    }

    /**
     * Check if a guard is included in this profile.
     */
    public function includesGuard(string $guardName): bool
    {
        // Empty guards array means all guards
        if (empty($this->guards)) {
            return true;
        }

        return in_array($guardName, $this->guards, true);
    }

    /**
     * Check if threat level meets threshold for action.
     */
    public function meetsThreshold(ThreatLevel $level): bool
    {
        return $level->weight() >= $this->threshold->weight();
    }

    /**
     * Convert to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'guards' => $this->guards,
            'mode' => $this->mode->value,
            'threshold' => $this->threshold->value,
            'enabled' => $this->enabled,
        ];
    }
}
