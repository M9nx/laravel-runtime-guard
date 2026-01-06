<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Integrations;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;

/**
 * OpenAPI-Aware Request Validator.
 *
 * Validates requests against OpenAPI/Swagger specifications.
 */
class OpenApiValidator
{
    protected ?array $spec = null;
    protected string $specPath;
    protected bool $enabled;
    protected array $skipPaths = [];

    public function __construct()
    {
        $this->specPath = config('runtime-guard.integrations.openapi.spec_path', base_path('openapi.yaml'));
        $this->enabled = config('runtime-guard.integrations.openapi.enabled', false);
        $this->skipPaths = config('runtime-guard.integrations.openapi.skip_paths', []);
    }

    /**
     * Load OpenAPI specification.
     */
    public function loadSpec(?string $path = null): bool
    {
        $path = $path ?? $this->specPath;

        if (!file_exists($path)) {
            return false;
        }

        $extension = pathinfo($path, PATHINFO_EXTENSION);

        try {
            $content = file_get_contents($path);

            if (in_array($extension, ['yaml', 'yml'])) {
                if (!function_exists('yaml_parse')) {
                    // Fallback for systems without yaml extension
                    $this->spec = $this->parseYamlFallback($content);
                } else {
                    $this->spec = yaml_parse($content);
                }
            } else {
                $this->spec = json_decode($content, true);
            }

            return is_array($this->spec);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Simple YAML parser fallback.
     */
    protected function parseYamlFallback(string $content): ?array
    {
        // Basic YAML parsing for simple specs
        // For complex specs, recommend installing symfony/yaml
        if (class_exists(\Symfony\Component\Yaml\Yaml::class)) {
            return \Symfony\Component\Yaml\Yaml::parse($content);
        }

        return null;
    }

    /**
     * Validate a request against the spec.
     */
    public function validate(string $method, string $path, array $data = []): ValidationResult
    {
        if (!$this->enabled || !$this->spec) {
            return new ValidationResult(true);
        }

        // Check skip paths
        foreach ($this->skipPaths as $skipPath) {
            if (fnmatch($skipPath, $path)) {
                return new ValidationResult(true);
            }
        }

        // Find matching path in spec
        $pathSpec = $this->findPathSpec($path);
        if (!$pathSpec) {
            return new ValidationResult(true, [], ['Path not defined in spec']);
        }

        // Get operation spec
        $method = strtolower($method);
        if (!isset($pathSpec[$method])) {
            return new ValidationResult(false, ['Method not allowed for this path']);
        }

        $operationSpec = $pathSpec[$method];
        $errors = [];
        $warnings = [];

        // Validate parameters
        if (isset($operationSpec['parameters'])) {
            $paramErrors = $this->validateParameters($operationSpec['parameters'], $data);
            $errors = array_merge($errors, $paramErrors);
        }

        // Validate request body
        if (isset($operationSpec['requestBody'])) {
            $bodyErrors = $this->validateRequestBody($operationSpec['requestBody'], $data);
            $errors = array_merge($errors, $bodyErrors);
        }

        return new ValidationResult(empty($errors), $errors, $warnings);
    }

    /**
     * Find path specification, handling path parameters.
     */
    protected function findPathSpec(string $path): ?array
    {
        if (!isset($this->spec['paths'])) {
            return null;
        }

        // Direct match
        if (isset($this->spec['paths'][$path])) {
            return $this->spec['paths'][$path];
        }

        // Try pattern matching for path parameters
        foreach ($this->spec['paths'] as $specPath => $spec) {
            $pattern = preg_replace('/\{[^}]+\}/', '[^/]+', $specPath);
            $pattern = '#^' . $pattern . '$#';

            if (preg_match($pattern, $path)) {
                return $spec;
            }
        }

        return null;
    }

    /**
     * Validate parameters against spec.
     */
    protected function validateParameters(array $paramSpecs, array $data): array
    {
        $errors = [];

        foreach ($paramSpecs as $paramSpec) {
            $name = $paramSpec['name'] ?? '';
            $required = $paramSpec['required'] ?? false;
            $location = $paramSpec['in'] ?? 'query';

            // Check required parameters
            if ($required && !isset($data[$name])) {
                $errors[] = "Required parameter '{$name}' is missing";
                continue;
            }

            if (!isset($data[$name])) {
                continue;
            }

            // Validate type if specified
            if (isset($paramSpec['schema'])) {
                $typeErrors = $this->validateType($data[$name], $paramSpec['schema'], $name);
                $errors = array_merge($errors, $typeErrors);
            }
        }

        return $errors;
    }

    /**
     * Validate request body against spec.
     */
    protected function validateRequestBody(array $bodySpec, array $data): array
    {
        $errors = [];
        $required = $bodySpec['required'] ?? false;

        if ($required && empty($data)) {
            return ['Request body is required'];
        }

        // Get content schema
        $content = $bodySpec['content'] ?? [];
        $schema = null;

        // Look for JSON schema
        if (isset($content['application/json']['schema'])) {
            $schema = $content['application/json']['schema'];
        }

        if ($schema) {
            $errors = $this->validateSchema($data, $schema);
        }

        return $errors;
    }

    /**
     * Validate data against a schema.
     */
    protected function validateSchema(array $data, array $schema, string $path = ''): array
    {
        $errors = [];

        // Handle $ref
        if (isset($schema['$ref'])) {
            $schema = $this->resolveRef($schema['$ref']);
            if (!$schema) {
                return $errors;
            }
        }

        $type = $schema['type'] ?? 'object';

        if ($type === 'object') {
            // Validate required properties
            $required = $schema['required'] ?? [];
            foreach ($required as $prop) {
                if (!array_key_exists($prop, $data)) {
                    $errors[] = "Required property '{$prop}' is missing" . ($path ? " at {$path}" : '');
                }
            }

            // Validate properties
            $properties = $schema['properties'] ?? [];
            foreach ($data as $key => $value) {
                if (isset($properties[$key])) {
                    $propPath = $path ? "{$path}.{$key}" : $key;

                    if (is_array($value) && isset($properties[$key]['type']) && $properties[$key]['type'] === 'object') {
                        $propErrors = $this->validateSchema($value, $properties[$key], $propPath);
                        $errors = array_merge($errors, $propErrors);
                    } else {
                        $typeErrors = $this->validateType($value, $properties[$key], $propPath);
                        $errors = array_merge($errors, $typeErrors);
                    }
                }
            }
        }

        return $errors;
    }

    /**
     * Validate a value's type.
     */
    protected function validateType(mixed $value, array $schema, string $path): array
    {
        $errors = [];
        $type = $schema['type'] ?? null;

        if (!$type) {
            return $errors;
        }

        $isValid = match ($type) {
            'string' => is_string($value),
            'integer' => is_int($value) || (is_string($value) && ctype_digit($value)),
            'number' => is_numeric($value),
            'boolean' => is_bool($value) || in_array($value, ['true', 'false', '0', '1']),
            'array' => is_array($value) && array_is_list($value),
            'object' => is_array($value) && !array_is_list($value),
            default => true,
        };

        if (!$isValid) {
            $errors[] = "Property '{$path}' must be of type {$type}";
        }

        // Validate string constraints
        if ($type === 'string' && is_string($value)) {
            if (isset($schema['minLength']) && strlen($value) < $schema['minLength']) {
                $errors[] = "Property '{$path}' must be at least {$schema['minLength']} characters";
            }
            if (isset($schema['maxLength']) && strlen($value) > $schema['maxLength']) {
                $errors[] = "Property '{$path}' must be at most {$schema['maxLength']} characters";
            }
            if (isset($schema['pattern']) && !preg_match('/' . $schema['pattern'] . '/', $value)) {
                $errors[] = "Property '{$path}' must match pattern {$schema['pattern']}";
            }
            if (isset($schema['enum']) && !in_array($value, $schema['enum'])) {
                $errors[] = "Property '{$path}' must be one of: " . implode(', ', $schema['enum']);
            }
        }

        // Validate number constraints
        if (in_array($type, ['integer', 'number']) && is_numeric($value)) {
            if (isset($schema['minimum']) && $value < $schema['minimum']) {
                $errors[] = "Property '{$path}' must be at least {$schema['minimum']}";
            }
            if (isset($schema['maximum']) && $value > $schema['maximum']) {
                $errors[] = "Property '{$path}' must be at most {$schema['maximum']}";
            }
        }

        return $errors;
    }

    /**
     * Resolve a $ref reference.
     */
    protected function resolveRef(string $ref): ?array
    {
        // Only handle internal refs for now
        if (!str_starts_with($ref, '#/')) {
            return null;
        }

        $path = explode('/', substr($ref, 2));
        $current = $this->spec;

        foreach ($path as $segment) {
            if (!isset($current[$segment])) {
                return null;
            }
            $current = $current[$segment];
        }

        return is_array($current) ? $current : null;
    }

    /**
     * Check if enabled.
     */
    public function isEnabled(): bool
    {
        return $this->enabled && $this->spec !== null;
    }

    /**
     * Get loaded spec.
     */
    public function getSpec(): ?array
    {
        return $this->spec;
    }
}

/**
 * Validation result container.
 */
class ValidationResult
{
    public function __construct(
        protected bool $valid,
        protected array $errors = [],
        protected array $warnings = []
    ) {}

    public function isValid(): bool
    {
        return $this->valid;
    }

    public function getErrors(): array
    {
        return $this->errors;
    }

    public function getWarnings(): array
    {
        return $this->warnings;
    }

    public function toArray(): array
    {
        return [
            'valid' => $this->valid,
            'errors' => $this->errors,
            'warnings' => $this->warnings,
        ];
    }
}
