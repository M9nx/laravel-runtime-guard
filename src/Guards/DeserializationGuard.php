<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Detects PHP Deserialization / Object Injection attacks.
 *
 * Catches serialized PHP objects that could lead to RCE.
 */
class DeserializationGuard extends AbstractGuard
{
    protected array $quickPatterns = ['serialized_object', 'phar_wrapper'];

    public function getName(): string
    {
        return 'deserialization';
    }

    protected function getPatterns(): array
    {
        return [
            'serialized_object' => [
                'O:\d+:"[^"]+":',           // PHP serialized object
                'a:\d+:{',                   // PHP serialized array
                'C:\d+:"[^"]+":',           // PHP custom serialized
                's:\d+:"',                   // PHP serialized string
                'i:\d+;',                    // PHP serialized integer
                'b:[01];',                   // PHP serialized boolean
                'N;',                        // PHP serialized null
            ],
            'phar_wrapper' => [
                'phar://',
                'compress\.zlib://phar',
                'compress\.bzip2://phar',
                'php://filter.*phar',
            ],
            'dangerous_classes' => [
                '__destruct',
                '__wakeup',
                '__unserialize',
                'Guzzle',
                'Monolog',
                'Symfony\\\\',
                'Illuminate\\\\',
                'Laravel\\\\',
            ],
            'encoded_serialized' => [
                'TzpcZCs6',                  // Base64 O:\d+:
                'YTpcZCs6',                  // Base64 a:\d+:
                'czpcZCs6',                  // Base64 s:\d+:
            ],
        ];
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        $normalized = $this->normalizeInput($input);

        if ($normalized === '') {
            return $this->pass();
        }

        // Check for PHAR wrapper (highest priority - direct RCE)
        if ($this->hasPharWrapper($normalized)) {
            return $this->threat(
                'PHAR deserialization attack detected',
                ThreatLevel::CRITICAL,
                ['type' => 'phar_wrapper', 'input_sample' => substr($normalized, 0, 200)]
            );
        }

        // Check for serialized PHP objects
        $serializedMatch = $this->findSerializedObject($normalized);
        if ($serializedMatch) {
            return $this->threat(
                'PHP object injection detected',
                ThreatLevel::CRITICAL,
                [
                    'type' => 'serialized_object',
                    'matched' => $serializedMatch['matched'],
                    'class' => $serializedMatch['class'] ?? 'unknown',
                ]
            );
        }

        // Check for base64-encoded serialized data
        if ($this->hasEncodedSerialized($normalized)) {
            return $this->threat(
                'Encoded serialized data detected',
                ThreatLevel::HIGH,
                ['type' => 'encoded_serialized', 'input_sample' => substr($normalized, 0, 200)]
            );
        }

        // Check for dangerous class names in input
        if ($this->hasDangerousClassReference($normalized)) {
            return $this->threat(
                'Dangerous class reference in input',
                ThreatLevel::MEDIUM,
                ['type' => 'class_reference', 'input_sample' => substr($normalized, 0, 200)]
            );
        }

        return $this->pass();
    }

    /**
     * Normalize input for inspection.
     */
    protected function normalizeInput(mixed $input): string
    {
        if (is_string($input)) {
            return $input;
        }

        if (is_array($input)) {
            return json_encode($input) ?: '';
        }

        return '';
    }

    /**
     * Check for PHAR protocol wrapper.
     */
    protected function hasPharWrapper(string $input): bool
    {
        $lower = strtolower($input);

        return str_contains($lower, 'phar://') ||
               str_contains($lower, 'compress.zlib://phar') ||
               str_contains($lower, 'compress.bzip2://phar');
    }

    /**
     * Find serialized PHP object in input.
     */
    protected function findSerializedObject(string $input): ?array
    {
        // Look for serialized object pattern: O:length:"classname":
        if (preg_match('/O:(\d+):"([^"]+)":\d+:{/', $input, $matches)) {
            return [
                'matched' => substr($matches[0], 0, 100),
                'class' => $matches[2],
                'class_length' => (int) $matches[1],
            ];
        }

        // Look for serialized array that might contain objects
        if (preg_match('/a:\d+:{.*O:\d+:"[^"]+"/', $input, $matches)) {
            return [
                'matched' => substr($matches[0], 0, 100),
                'class' => 'embedded',
            ];
        }

        // Custom serialization
        if (preg_match('/C:(\d+):"([^"]+)"/', $input, $matches)) {
            return [
                'matched' => substr($matches[0], 0, 100),
                'class' => $matches[2],
            ];
        }

        return null;
    }

    /**
     * Check for base64-encoded serialized data.
     */
    protected function hasEncodedSerialized(string $input): bool
    {
        // Find potential base64 strings
        if (!preg_match_all('/[A-Za-z0-9+\/]{20,}={0,2}/', $input, $matches)) {
            return false;
        }

        foreach ($matches[0] as $potential) {
            $decoded = base64_decode($potential, true);
            if ($decoded === false) {
                continue;
            }

            // Check if decoded content looks like serialized PHP
            if (preg_match('/^[OaCsbidN]:/', $decoded)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for dangerous class references.
     */
    protected function hasDangerousClassReference(string $input): bool
    {
        $dangerousPatterns = [
            '__destruct',
            '__wakeup',
            '__unserialize',
            'GuzzleHttp\\',
            'Monolog\\',
            'Symfony\\Component',
            'Illuminate\\Support\\',
            'phpggc',
        ];

        $lower = strtolower($input);

        foreach ($dangerousPatterns as $pattern) {
            if (str_contains($lower, strtolower($pattern))) {
                return true;
            }
        }

        return false;
    }
}
