<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Profiles;

use M9nx\RuntimeGuard\Support\InspectionContext;

/**
 * Resolves which guard profile applies to a given context.
 */
class ProfileResolver
{
    /**
     * @var array<string, GuardProfile>
     */
    private array $profiles = [];

    /**
     * @var array<string, string>
     */
    private array $routeMappings = [];

    private ?GuardProfile $defaultProfile = null;

    /**
     * Create from configuration.
     */
    public static function fromConfig(array $config): self
    {
        $resolver = new self();

        // Register profiles
        foreach ($config['profiles'] ?? [] as $name => $profileConfig) {
            $resolver->registerProfile(GuardProfile::fromConfig($name, $profileConfig));
        }

        // Register route mappings
        foreach ($config['routes'] ?? [] as $pattern => $profileName) {
            $resolver->mapRoute($pattern, $profileName);
        }

        // Set default profile
        if (isset($config['default_profile'])) {
            $resolver->setDefaultProfile($config['default_profile']);
        }

        return $resolver;
    }

    /**
     * Register a profile.
     */
    public function registerProfile(GuardProfile $profile): self
    {
        $this->profiles[$profile->name] = $profile;

        return $this;
    }

    /**
     * Map a route pattern to a profile.
     */
    public function mapRoute(string $pattern, string $profileName): self
    {
        $this->routeMappings[$pattern] = $profileName;

        return $this;
    }

    /**
     * Set the default profile.
     */
    public function setDefaultProfile(string $profileName): self
    {
        if (isset($this->profiles[$profileName])) {
            $this->defaultProfile = $this->profiles[$profileName];
        }

        return $this;
    }

    /**
     * Resolve the profile for a given context.
     */
    public function resolve(InspectionContext $context): ?GuardProfile
    {
        // Check route mappings
        foreach ($this->routeMappings as $pattern => $profileName) {
            if ($context->pathMatches($pattern)) {
                return $this->profiles[$profileName] ?? null;
            }
        }

        // Check route name
        $routeName = $context->routeName();
        if ($routeName && isset($this->routeMappings[$routeName])) {
            return $this->profiles[$this->routeMappings[$routeName]] ?? null;
        }

        return $this->defaultProfile;
    }

    /**
     * Get a profile by name.
     */
    public function getProfile(string $name): ?GuardProfile
    {
        return $this->profiles[$name] ?? null;
    }

    /**
     * Get all registered profiles.
     *
     * @return array<string, GuardProfile>
     */
    public function getProfiles(): array
    {
        return $this->profiles;
    }

    /**
     * Check if a profile exists.
     */
    public function hasProfile(string $name): bool
    {
        return isset($this->profiles[$name]);
    }

    /**
     * Get route mappings.
     *
     * @return array<string, string>
     */
    public function getRouteMappings(): array
    {
        return $this->routeMappings;
    }
}
