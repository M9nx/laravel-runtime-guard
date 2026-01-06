<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Detects potential Cross-Site Scripting (XSS) attacks.
 */
class XssGuard extends AbstractGuard
{
    /**
     * Quick scan patterns (lightweight, high-confidence checks).
     *
     * @var array<string>
     */
    protected array $quickPatterns = ['script_tags', 'event_handlers'];

    /**
     * Deep inspection patterns.
     *
     * @var array<string>
     */
    protected array $deepPatterns = ['script_tags', 'event_handlers', 'javascript_uri', 'data_uri', 'encoding'];

    public function getName(): string
    {
        return 'xss';
    }

    /**
     * {@inheritdoc}
     */
    protected function getPatterns(): array
    {
        return array_merge($this->getDefaultPatterns(), $this->getConfig('patterns', []));
    }

    /**
     * Default XSS detection patterns.
     *
     * @return array<string, array<string>>
     */
    protected function getDefaultPatterns(): array
    {
        return [
            'script_tags' => [
                '<script[^>]*>',
                '</script>',
                '<script\s+',
            ],

            'event_handlers' => [
                '\bon\w+\s*=',
                'onerror\s*=',
                'onload\s*=',
                'onclick\s*=',
                'onmouseover\s*=',
                'onfocus\s*=',
                'onblur\s*=',
                'onsubmit\s*=',
                'onchange\s*=',
                'oninput\s*=',
            ],

            'javascript_uri' => [
                'javascript\s*:',
                'vbscript\s*:',
                'livescript\s*:',
            ],

            'data_uri' => [
                'data\s*:[^,]*;base64',
                'data\s*:text/html',
            ],

            'encoding' => [
                '&#x?[0-9a-f]+;?',
                '\\\\x[0-9a-f]{2}',
                '\\\\u[0-9a-f]{4}',
                '%3c%73%63%72%69%70%74', // <script URL encoded
            ],

            'html_injection' => [
                '<iframe[^>]*>',
                '<object[^>]*>',
                '<embed[^>]*>',
                '<svg[^>]*onload',
                '<img[^>]*onerror',
                '<body[^>]*onload',
                '<input[^>]*onfocus',
                '<marquee[^>]*onstart',
                '<video[^>]*onloadeddata',
                '<audio[^>]*onloadeddata',
                '<details[^>]*ontoggle',
            ],

            'expression' => [
                'expression\s*\(',
                'url\s*\(\s*["\']?\s*javascript',
                '-moz-binding',
            ],
        ];
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        $normalized = $this->normalizeInput($input);

        if ($normalized === '') {
            return $this->pass();
        }

        // Check all patterns
        foreach ($this->compiledPatterns as $patternName => $pattern) {
            if (preg_match($pattern, $normalized, $matches)) {
                return $this->createXssResult($patternName, $matches[0], $normalized);
            }
        }

        // Additional checks
        if ($this->hasEncodedXss($normalized)) {
            return $this->threat(
                'Encoded XSS payload detected',
                ThreatLevel::HIGH,
                ['type' => 'encoded_xss', 'input_sample' => substr($normalized, 0, 200)]
            );
        }

        if ($this->hasDomXss($normalized)) {
            return $this->threat(
                'Potential DOM-based XSS detected',
                ThreatLevel::MEDIUM,
                ['type' => 'dom_xss', 'input_sample' => substr($normalized, 0, 200)]
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
            return $this->decodeAndLowercase($input);
        }

        if (is_array($input)) {
            return $this->decodeAndLowercase($this->flattenArray($input));
        }

        return '';
    }

    /**
     * Decode common encodings and lowercase.
     */
    protected function decodeAndLowercase(string $input): string
    {
        // Decode HTML entities
        $decoded = html_entity_decode($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Decode URL encoding
        $decoded = urldecode($decoded);

        // Normalize whitespace
        $decoded = preg_replace('/\s+/', ' ', $decoded) ?? $decoded;

        return strtolower($decoded);
    }

    /**
     * Flatten array to string for inspection.
     */
    protected function flattenArray(array $data, int $depth = 0): string
    {
        if ($depth > 10) {
            return '';
        }

        $parts = [];
        foreach ($data as $value) {
            if (is_string($value)) {
                $parts[] = $value;
            } elseif (is_array($value)) {
                $parts[] = $this->flattenArray($value, $depth + 1);
            }
        }

        return implode(' ', $parts);
    }

    /**
     * Check for encoded XSS patterns.
     */
    protected function hasEncodedXss(string $input): bool
    {
        // Check for double-encoded patterns
        $doubleDecoded = urldecode(urldecode($input));
        if ($doubleDecoded !== $input) {
            // Re-check with double-decoded input
            foreach (['script_tags', 'event_handlers', 'javascript_uri'] as $pattern) {
                if (isset($this->compiledPatterns[$pattern]) &&
                    preg_match($this->compiledPatterns[$pattern], $doubleDecoded)) {
                    return true;
                }
            }
        }

        // Check for Unicode escapes that might hide scripts
        if (preg_match('/\\\\u00[0-9a-f]{2}/i', $input)) {
            $unicodeDecoded = preg_replace_callback(
                '/\\\\u([0-9a-f]{4})/i',
                fn ($m) => chr(hexdec($m[1])),
                $input
            ) ?? $input;

            if (stripos($unicodeDecoded, '<script') !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for DOM-based XSS patterns.
     */
    protected function hasDomXss(string $input): bool
    {
        $domSinks = [
            'document.write',
            'document.writeln',
            '.innerhtml',
            '.outerhtml',
            'eval(',
            'settimeout(',
            'setinterval(',
            'function(',
            'new function',
        ];

        foreach ($domSinks as $sink) {
            if (stripos($input, $sink) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Create XSS threat result.
     */
    protected function createXssResult(string $patternName, string $matched, string $fullInput): GuardResultInterface
    {
        $level = match ($patternName) {
            'script_tags', 'javascript_uri' => ThreatLevel::CRITICAL,
            'event_handlers', 'html_injection' => ThreatLevel::HIGH,
            'encoding', 'expression' => ThreatLevel::MEDIUM,
            default => ThreatLevel::MEDIUM,
        };

        return $this->threat(
            "XSS attempt detected: {$patternName}",
            $level,
            [
                'pattern' => $patternName,
                'matched' => substr($matched, 0, 100),
                'input_sample' => substr($fullInput, 0, 200),
            ]
        );
    }
}
