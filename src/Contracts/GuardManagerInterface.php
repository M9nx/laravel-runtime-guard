<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Contracts;

/**
 * Interface for the central guard registry and orchestrator.
 */
interface GuardManagerInterface
{
    /**
     * Register a guard instance.
     */
    public function register(GuardInterface $guard): static;

    /**
     * Register a guard by class name (lazy loading).
     *
     * @param  class-string<GuardInterface>  $guardClass
     */
    public function registerClass(string $guardClass): static;

    /**
     * Get a registered guard by name.
     */
    public function get(string $name): ?GuardInterface;

    /**
     * Determine if a guard is registered.
     */
    public function has(string $name): bool;

    /**
     * Get all registered guards.
     *
     * @return array<string, GuardInterface>
     */
    public function all(): array;

    /**
     * Get all enabled guards, sorted by priority.
     *
     * @return array<GuardInterface>
     */
    public function enabled(): array;

    /**
     * Run all enabled guards against the given input.
     *
     * @param  mixed  $input
     * @param  array<string, mixed>  $context
     * @return array<GuardResultInterface>
     */
    public function inspect(mixed $input, array $context = []): array;

    /**
     * Run a specific guard by name.
     *
     * @param  array<string, mixed>  $context
     */
    public function inspectWith(string $guardName, mixed $input, array $context = []): GuardResultInterface;
}
