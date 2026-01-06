<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Support;

/**
 * Handles bounded input inspection to prevent resource exhaustion.
 */
final class InputLimiter
{
    public function __construct(
        private readonly int $maxBytes = 65536,
        private readonly int $maxArrayDepth = 10,
        private readonly int $maxArrayItems = 1000,
    ) {}

    /**
     * Limit string input to max bytes.
     */
    public function limitString(string $input): string
    {
        if (strlen($input) <= $this->maxBytes) {
            return $input;
        }

        return substr($input, 0, $this->maxBytes);
    }

    /**
     * Limit array input by depth and item count.
     *
     * @return array<mixed>
     */
    public function limitArray(array $input, int $currentDepth = 0): array
    {
        if ($currentDepth >= $this->maxArrayDepth) {
            return ['__truncated__' => 'max depth exceeded'];
        }

        $result = [];
        $count = 0;

        foreach ($input as $key => $value) {
            if ($count >= $this->maxArrayItems) {
                $result['__truncated__'] = 'max items exceeded';
                break;
            }

            if (is_array($value)) {
                $result[$key] = $this->limitArray($value, $currentDepth + 1);
            } elseif (is_string($value)) {
                $result[$key] = $this->limitString($value);
            } else {
                $result[$key] = $value;
            }

            $count++;
        }

        return $result;
    }

    /**
     * Limit any input type.
     */
    public function limit(mixed $input): mixed
    {
        if (is_string($input)) {
            return $this->limitString($input);
        }

        if (is_array($input)) {
            return $this->limitArray($input);
        }

        return $input;
    }

    /**
     * Check if input exceeds limits without modifying.
     */
    public function exceedsLimits(mixed $input): bool
    {
        if (is_string($input)) {
            return strlen($input) > $this->maxBytes;
        }

        if (is_array($input)) {
            return $this->checkArrayLimits($input);
        }

        return false;
    }

    /**
     * Get stats about the input.
     *
     * @return array{bytes: int, depth: int, items: int, exceeds: bool}
     */
    public function analyze(mixed $input): array
    {
        $bytes = is_string($input) ? strlen($input) : strlen(json_encode($input) ?: '');
        $depth = is_array($input) ? $this->measureDepth($input) : 0;
        $items = is_array($input) ? $this->countItems($input) : 0;

        return [
            'bytes' => $bytes,
            'depth' => $depth,
            'items' => $items,
            'exceeds' => $bytes > $this->maxBytes || $depth > $this->maxArrayDepth || $items > $this->maxArrayItems,
        ];
    }

    private function checkArrayLimits(array $input, int $depth = 0, int &$totalItems = 0): bool
    {
        if ($depth > $this->maxArrayDepth) {
            return true;
        }

        foreach ($input as $value) {
            $totalItems++;

            if ($totalItems > $this->maxArrayItems) {
                return true;
            }

            if (is_array($value) && $this->checkArrayLimits($value, $depth + 1, $totalItems)) {
                return true;
            }

            if (is_string($value) && strlen($value) > $this->maxBytes) {
                return true;
            }
        }

        return false;
    }

    private function measureDepth(array $input, int $currentDepth = 0): int
    {
        $maxDepth = $currentDepth;

        foreach ($input as $value) {
            if (is_array($value)) {
                $maxDepth = max($maxDepth, $this->measureDepth($value, $currentDepth + 1));
            }
        }

        return $maxDepth;
    }

    private function countItems(array $input): int
    {
        $count = count($input);

        foreach ($input as $value) {
            if (is_array($value)) {
                $count += $this->countItems($value);
            }
        }

        return $count;
    }
}
