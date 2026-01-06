<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Plugins;

use Illuminate\Support\Facades\File;
use M9nx\RuntimeGuard\Contracts\GuardInterface;

/**
 * Guard plugin manager for loading external guards.
 *
 * Supports auto-discovery of guards from Composer packages
 * via extra.runtime-guard.guards in composer.json.
 */
class PluginManager
{
    /**
     * @var array<string, array{class: string, config: array}>
     */
    private array $plugins = [];

    private bool $autoDiscoveryEnabled;
    private array $trustedVendors;
    private ?string $pluginDirectory;

    public function __construct(array $config = [])
    {
        $this->autoDiscoveryEnabled = $config['auto_discovery'] ?? true;
        $this->trustedVendors = $config['trusted_vendors'] ?? [];
        $this->pluginDirectory = $config['plugin_directory'] ?? null;
    }

    /**
     * Create from configuration.
     */
    public static function fromConfig(array $config): self
    {
        return new self($config);
    }

    /**
     * Discover plugins from installed packages.
     */
    public function discover(): self
    {
        if (!$this->autoDiscoveryEnabled) {
            return $this;
        }

        $this->discoverFromComposer();
        $this->discoverFromDirectory();

        return $this;
    }

    /**
     * Register a plugin manually.
     */
    public function register(string $name, string $guardClass, array $config = []): self
    {
        if (!is_subclass_of($guardClass, GuardInterface::class)) {
            throw new \InvalidArgumentException(
                "Guard class {$guardClass} must implement GuardInterface"
            );
        }

        $this->plugins[$name] = [
            'class' => $guardClass,
            'config' => $config,
        ];

        return $this;
    }

    /**
     * Get all registered plugins.
     *
     * @return array<string, array{class: string, config: array}>
     */
    public function all(): array
    {
        return $this->plugins;
    }

    /**
     * Check if a plugin is registered.
     */
    public function has(string $name): bool
    {
        return isset($this->plugins[$name]);
    }

    /**
     * Get a plugin by name.
     */
    public function get(string $name): ?array
    {
        return $this->plugins[$name] ?? null;
    }

    /**
     * Create guard instance from plugin.
     */
    public function createGuard(string $name): ?GuardInterface
    {
        $plugin = $this->get($name);

        if (!$plugin) {
            return null;
        }

        $class = $plugin['class'];
        $config = $plugin['config'];

        return new $class($config);
    }

    /**
     * Discover plugins from Composer packages.
     */
    private function discoverFromComposer(): void
    {
        $composerPath = base_path('vendor/composer/installed.json');

        if (!File::exists($composerPath)) {
            return;
        }

        $installed = json_decode(File::get($composerPath), true);
        $packages = $installed['packages'] ?? $installed ?? [];

        foreach ($packages as $package) {
            $this->processPackage($package);
        }
    }

    /**
     * Process a single Composer package.
     */
    private function processPackage(array $package): void
    {
        $extra = $package['extra'] ?? [];
        $runtimeGuard = $extra['runtime-guard'] ?? [];
        $guards = $runtimeGuard['guards'] ?? [];

        if (empty($guards)) {
            return;
        }

        // Check if vendor is trusted
        $packageName = $package['name'] ?? '';
        $vendor = explode('/', $packageName)[0] ?? '';

        if (!empty($this->trustedVendors) && !in_array($vendor, $this->trustedVendors)) {
            // Skip untrusted vendors unless explicitly approved
            return;
        }

        foreach ($guards as $name => $guardConfig) {
            if (is_string($guardConfig)) {
                // Simple class reference
                $this->plugins[$name] = [
                    'class' => $guardConfig,
                    'config' => [],
                    'package' => $packageName,
                ];
            } elseif (is_array($guardConfig) && isset($guardConfig['class'])) {
                $this->plugins[$name] = [
                    'class' => $guardConfig['class'],
                    'config' => $guardConfig['config'] ?? [],
                    'package' => $packageName,
                ];
            }
        }
    }

    /**
     * Discover plugins from local directory.
     */
    private function discoverFromDirectory(): void
    {
        if (!$this->pluginDirectory || !File::isDirectory($this->pluginDirectory)) {
            return;
        }

        $files = File::glob($this->pluginDirectory . '/*.php');

        foreach ($files as $file) {
            $this->processPluginFile($file);
        }
    }

    /**
     * Process a plugin file.
     */
    private function processPluginFile(string $file): void
    {
        // Extract class name from file
        $content = File::get($file);

        // Match namespace and class
        if (!preg_match('/namespace\s+([^;]+);/', $content, $nsMatch)) {
            return;
        }

        if (!preg_match('/class\s+(\w+)/', $content, $classMatch)) {
            return;
        }

        $className = $nsMatch[1] . '\\' . $classMatch[1];

        // Check if it's a valid guard
        if (!class_exists($className)) {
            // Try to autoload
            require_once $file;
        }

        if (!class_exists($className) || !is_subclass_of($className, GuardInterface::class)) {
            return;
        }

        // Use class name as plugin name
        $name = strtolower($classMatch[1]);
        $name = preg_replace('/guard$/i', '', $name);

        $this->plugins[$name] = [
            'class' => $className,
            'config' => [],
            'source' => 'directory',
        ];
    }

    /**
     * Validate a guard class.
     */
    public function validateGuardClass(string $class): array
    {
        $errors = [];

        if (!class_exists($class)) {
            $errors[] = "Class {$class} does not exist";
            return $errors;
        }

        if (!is_subclass_of($class, GuardInterface::class)) {
            $errors[] = "Class {$class} must implement GuardInterface";
        }

        $reflection = new \ReflectionClass($class);

        if ($reflection->isAbstract()) {
            $errors[] = "Class {$class} cannot be abstract";
        }

        if (!$reflection->isInstantiable()) {
            $errors[] = "Class {$class} must be instantiable";
        }

        return $errors;
    }

    /**
     * Get statistics.
     */
    public function getStats(): array
    {
        $bySource = [];
        foreach ($this->plugins as $plugin) {
            $source = $plugin['source'] ?? $plugin['package'] ?? 'manual';
            $bySource[$source] = ($bySource[$source] ?? 0) + 1;
        }

        return [
            'total_plugins' => count($this->plugins),
            'by_source' => $bySource,
            'auto_discovery' => $this->autoDiscoveryEnabled,
            'trusted_vendors' => $this->trustedVendors,
        ];
    }
}
