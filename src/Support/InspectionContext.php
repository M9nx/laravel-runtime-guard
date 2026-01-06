<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;

/**
 * Rich context object passed to guards during inspection.
 *
 * Provides safe, typed accessors to request/environment data.
 * Uses lazy resolution to avoid hydrating unused data.
 */
final class InspectionContext
{
    private ?Request $resolvedRequest = null;

    private ?Authenticatable $resolvedUser = null;

    private ?Route $resolvedRoute = null;

    private bool $requestResolved = false;

    private bool $userResolved = false;

    private bool $routeResolved = false;

    /**
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        private readonly ?\Closure $requestResolver = null,
        private readonly ?\Closure $userResolver = null,
        private readonly ?\Closure $routeResolver = null,
        private readonly array $metadata = [],
        private readonly ?string $inputHash = null,
        private readonly int $inputLength = 0,
        private readonly string $inputType = 'unknown',
    ) {}

    /**
     * Create context from current Laravel request.
     */
    public static function fromRequest(Request $request, array $metadata = []): self
    {
        $input = $request->all();
        $inputString = json_encode($input) ?: '';

        return new self(
            requestResolver: fn () => $request,
            userResolver: fn () => $request->user(),
            routeResolver: fn () => $request->route(),
            metadata: $metadata,
            inputHash: hash('xxh3', $inputString),
            inputLength: strlen($inputString),
            inputType: 'request',
        );
    }

    /**
     * Create context for raw input inspection.
     */
    public static function forInput(mixed $input, array $metadata = []): self
    {
        $inputString = is_string($input) ? $input : (json_encode($input) ?: '');

        return new self(
            metadata: $metadata,
            inputHash: hash('xxh3', $inputString),
            inputLength: strlen($inputString),
            inputType: gettype($input),
        );
    }

    /**
     * Create an empty context.
     */
    public static function empty(): self
    {
        return new self();
    }

    public function request(): ?Request
    {
        if (! $this->requestResolved) {
            $this->resolvedRequest = $this->requestResolver ? ($this->requestResolver)() : null;
            $this->requestResolved = true;
        }

        return $this->resolvedRequest;
    }

    public function user(): ?Authenticatable
    {
        if (! $this->userResolved) {
            $this->resolvedUser = $this->userResolver ? ($this->userResolver)() : null;
            $this->userResolved = true;
        }

        return $this->resolvedUser;
    }

    public function route(): ?Route
    {
        if (! $this->routeResolved) {
            $this->resolvedRoute = $this->routeResolver ? ($this->routeResolver)() : null;
            $this->routeResolved = true;
        }

        return $this->resolvedRoute;
    }

    public function ip(): ?string
    {
        return $this->request()?->ip();
    }

    public function userId(): int|string|null
    {
        return $this->user()?->getAuthIdentifier();
    }

    public function routeName(): ?string
    {
        return $this->route()?->getName();
    }

    public function routeUri(): ?string
    {
        return $this->route()?->uri();
    }

    public function isApi(): bool
    {
        $request = $this->request();
        if (! $request) {
            return false;
        }

        return $request->is('api/*') || $request->expectsJson();
    }

    public function isAuthenticated(): bool
    {
        return $this->user() !== null;
    }

    public function method(): string
    {
        return $this->request()?->method() ?? 'UNKNOWN';
    }

    public function contentType(): ?string
    {
        return $this->request()?->header('Content-Type');
    }

    public function userAgent(): ?string
    {
        return $this->request()?->userAgent();
    }

    public function hasStringInput(): bool
    {
        return $this->inputType === 'string';
    }

    public function hasArrayInput(): bool
    {
        return $this->inputType === 'array';
    }

    public function inputLength(): int
    {
        return $this->inputLength;
    }

    public function inputHash(): ?string
    {
        return $this->inputHash;
    }

    public function inputType(): string
    {
        return $this->inputType;
    }

    /**
     * Get correlation key for threat correlation.
     */
    public function correlationKey(string $groupBy = 'ip'): string
    {
        return match ($groupBy) {
            'ip' => $this->ip() ?? 'unknown',
            'user_id' => (string) ($this->userId() ?? 'anonymous'),
            'session' => $this->request()?->session()?->getId() ?? 'no-session',
            'route' => $this->routeName() ?? $this->routeUri() ?? 'unknown',
            default => $this->ip() ?? 'unknown',
        };
    }

    /**
     * Get metadata value.
     */
    public function getMeta(string $key, mixed $default = null): mixed
    {
        return $this->metadata[$key] ?? $default;
    }

    /**
     * Get all metadata.
     *
     * @return array<string, mixed>
     */
    public function getAllMeta(): array
    {
        return $this->metadata;
    }

    /**
     * Create a new context with additional metadata.
     */
    public function withMeta(array $metadata): self
    {
        return new self(
            requestResolver: $this->requestResolver,
            userResolver: $this->userResolver,
            routeResolver: $this->routeResolver,
            metadata: array_merge($this->metadata, $metadata),
            inputHash: $this->inputHash,
            inputLength: $this->inputLength,
            inputType: $this->inputType,
        );
    }

    /**
     * Check if path matches pattern.
     */
    public function pathMatches(string $pattern): bool
    {
        $uri = $this->routeUri() ?? $this->request()?->path() ?? '';

        return fnmatch($pattern, $uri);
    }

    /**
     * Convert to array for logging/serialization.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ip' => $this->ip(),
            'user_id' => $this->userId(),
            'route' => $this->routeName(),
            'method' => $this->method(),
            'is_api' => $this->isApi(),
            'input_type' => $this->inputType,
            'input_length' => $this->inputLength,
            'metadata' => $this->metadata,
        ];
    }
}
