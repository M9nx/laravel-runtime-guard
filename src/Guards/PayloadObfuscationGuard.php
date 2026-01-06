<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardInterface;
use M9nx\RuntimeGuard\Context\RuntimeContext;
use M9nx\RuntimeGuard\Results\GuardResult;

/**
 * Payload Obfuscation Guard.
 *
 * Detects attempts to bypass security through obfuscation:
 * - Unicode/encoding tricks (homoglyphs, zero-width chars)
 * - Double/triple encoding
 * - Case manipulation bypass attempts
 * - Comment injection within payloads
 * - Null byte injection
 * - Character set confusion
 */
class PayloadObfuscationGuard implements GuardInterface
{
    private bool $enabled;
    private bool $detectUnicodeHomoglyphs;
    private bool $detectMultipleEncoding;
    private bool $detectZeroWidthChars;
    private bool $detectNullBytes;
    private bool $detectCommentInjection;
    private int $maxDecodingIterations;
    private array $suspiciousEncodings;

    public function __construct(array $config = [])
    {
        $this->enabled = $config['enabled'] ?? true;
        $this->detectUnicodeHomoglyphs = $config['detect_unicode_homoglyphs'] ?? true;
        $this->detectMultipleEncoding = $config['detect_multiple_encoding'] ?? true;
        $this->detectZeroWidthChars = $config['detect_zero_width_chars'] ?? true;
        $this->detectNullBytes = $config['detect_null_bytes'] ?? true;
        $this->detectCommentInjection = $config['detect_comment_injection'] ?? true;
        $this->maxDecodingIterations = $config['max_decoding_iterations'] ?? 5;
        $this->suspiciousEncodings = $config['suspicious_encodings'] ?? ['base64', 'hex', 'url', 'html'];
    }

    public function inspect(RuntimeContext $context): GuardResult
    {
        if (!$this->enabled) {
            return GuardResult::pass($this->getName());
        }

        $request = $context->getRequest();
        $threats = [];
        $metadata = [];

        // Collect all input for inspection
        $inputs = $this->collectInputs($request);

        foreach ($inputs as $location => $values) {
            foreach ($values as $key => $value) {
                if (!is_string($value)) {
                    continue;
                }

                $obfuscations = $this->detectObfuscation($value);

                foreach ($obfuscations as $obfuscation) {
                    $threats[] = array_merge($obfuscation, [
                        'location' => $location,
                        'parameter' => $key,
                    ]);
                }
            }
        }

        $metadata['inputs_checked'] = array_sum(array_map('count', $inputs));
        $metadata['obfuscations_found'] = count($threats);

        if (!empty($threats)) {
            return GuardResult::fail($this->getName(), $threats)
                ->withMetadata($metadata);
        }

        return GuardResult::pass($this->getName())
            ->withMetadata($metadata);
    }

    /**
     * Collect all inputs from request.
     */
    private function collectInputs(object $request): array
    {
        return [
            'query' => $request->query() ?? [],
            'body' => $request->post() ?? [],
            'headers' => $this->getStringHeaders($request),
        ];
    }

    /**
     * Get string headers only.
     */
    private function getStringHeaders(object $request): array
    {
        $headers = [];
        $checkHeaders = ['User-Agent', 'Referer', 'Cookie', 'Authorization', 'X-Forwarded-For'];

        foreach ($checkHeaders as $header) {
            $value = $request->header($header);
            if ($value) {
                $headers[$header] = $value;
            }
        }

        return $headers;
    }

    /**
     * Detect obfuscation techniques.
     */
    private function detectObfuscation(string $input): array
    {
        $threats = [];

        // Check for Unicode homoglyphs
        if ($this->detectUnicodeHomoglyphs) {
            $homoglyphResult = $this->checkHomoglyphs($input);
            if ($homoglyphResult) {
                $threats[] = $homoglyphResult;
            }
        }

        // Check for zero-width characters
        if ($this->detectZeroWidthChars) {
            $zeroWidthResult = $this->checkZeroWidthChars($input);
            if ($zeroWidthResult) {
                $threats[] = $zeroWidthResult;
            }
        }

        // Check for null bytes
        if ($this->detectNullBytes) {
            $nullByteResult = $this->checkNullBytes($input);
            if ($nullByteResult) {
                $threats[] = $nullByteResult;
            }
        }

        // Check for multiple encoding layers
        if ($this->detectMultipleEncoding) {
            $encodingResult = $this->checkMultipleEncoding($input);
            if ($encodingResult) {
                $threats[] = $encodingResult;
            }
        }

        // Check for comment injection
        if ($this->detectCommentInjection) {
            $commentResult = $this->checkCommentInjection($input);
            if ($commentResult) {
                $threats[] = $commentResult;
            }
        }

        return $threats;
    }

    /**
     * Check for Unicode homoglyphs (lookalike characters).
     */
    private function checkHomoglyphs(string $input): ?array
    {
        // Common homoglyph mappings (visual lookalikes)
        $homoglyphs = [
            // Cyrillic lookalikes
            'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c',
            'у' => 'y', 'х' => 'x', 'А' => 'A', 'В' => 'B', 'Е' => 'E',
            'К' => 'K', 'М' => 'M', 'Н' => 'H', 'О' => 'O', 'Р' => 'P',
            'С' => 'C', 'Т' => 'T', 'Х' => 'X',
            // Greek lookalikes
            'Α' => 'A', 'Β' => 'B', 'Ε' => 'E', 'Ζ' => 'Z', 'Η' => 'H',
            'Ι' => 'I', 'Κ' => 'K', 'Μ' => 'M', 'Ν' => 'N', 'Ο' => 'O',
            'Ρ' => 'P', 'Τ' => 'T', 'Υ' => 'Y', 'Χ' => 'X',
            // Special characters
            'ⅰ' => 'i', 'ⅱ' => 'ii', 'ⅲ' => 'iii',
            'ℓ' => 'l', '№' => 'No',
        ];

        $found = [];
        foreach ($homoglyphs as $homoglyph => $ascii) {
            if (mb_strpos($input, $homoglyph) !== false) {
                $found[] = $homoglyph;
            }
        }

        if (!empty($found)) {
            return [
                'type' => 'unicode_homoglyph',
                'severity' => 'high',
                'message' => 'Unicode homoglyph characters detected (potential bypass attempt)',
                'details' => [
                    'characters_found' => $found,
                    'count' => count($found),
                ],
            ];
        }

        return null;
    }

    /**
     * Check for zero-width characters.
     */
    private function checkZeroWidthChars(string $input): ?array
    {
        $zeroWidthChars = [
            "\u{200B}" => 'ZERO WIDTH SPACE',
            "\u{200C}" => 'ZERO WIDTH NON-JOINER',
            "\u{200D}" => 'ZERO WIDTH JOINER',
            "\u{FEFF}" => 'BYTE ORDER MARK',
            "\u{00AD}" => 'SOFT HYPHEN',
            "\u{200E}" => 'LEFT-TO-RIGHT MARK',
            "\u{200F}" => 'RIGHT-TO-LEFT MARK',
            "\u{2060}" => 'WORD JOINER',
            "\u{2061}" => 'FUNCTION APPLICATION',
            "\u{2062}" => 'INVISIBLE TIMES',
            "\u{2063}" => 'INVISIBLE SEPARATOR',
            "\u{2064}" => 'INVISIBLE PLUS',
        ];

        $found = [];
        foreach ($zeroWidthChars as $char => $name) {
            if (strpos($input, $char) !== false) {
                $found[] = $name;
            }
        }

        if (!empty($found)) {
            return [
                'type' => 'zero_width_chars',
                'severity' => 'high',
                'message' => 'Zero-width characters detected (potential obfuscation)',
                'details' => [
                    'characters_found' => $found,
                    'count' => count($found),
                ],
            ];
        }

        return null;
    }

    /**
     * Check for null bytes.
     */
    private function checkNullBytes(string $input): ?array
    {
        $nullPatterns = [
            "\x00" => 'null byte',
            '%00' => 'url-encoded null',
            '\0' => 'escaped null',
            '\x00' => 'hex null',
        ];

        $found = [];
        foreach ($nullPatterns as $pattern => $name) {
            if (strpos($input, $pattern) !== false) {
                $found[] = $name;
            }
        }

        if (!empty($found)) {
            return [
                'type' => 'null_byte_injection',
                'severity' => 'critical',
                'message' => 'Null byte injection detected',
                'details' => [
                    'patterns_found' => $found,
                ],
            ];
        }

        return null;
    }

    /**
     * Check for multiple encoding layers.
     */
    private function checkMultipleEncoding(string $input): ?array
    {
        $decodingLayers = 0;
        $current = $input;
        $encodingsUsed = [];

        for ($i = 0; $i < $this->maxDecodingIterations; $i++) {
            $decoded = $current;
            $encodingFound = null;

            // Try URL decoding
            $urlDecoded = urldecode($current);
            if ($urlDecoded !== $current && $this->containsEncodedChars($current, 'url')) {
                $decoded = $urlDecoded;
                $encodingFound = 'url';
            }

            // Try HTML entity decoding
            if ($decoded === $current) {
                $htmlDecoded = html_entity_decode($current, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                if ($htmlDecoded !== $current) {
                    $decoded = $htmlDecoded;
                    $encodingFound = 'html';
                }
            }

            // Try base64 decoding (if it looks like base64)
            if ($decoded === $current && $this->looksLikeBase64($current)) {
                $base64Decoded = base64_decode($current, true);
                if ($base64Decoded !== false && $this->isPrintable($base64Decoded)) {
                    $decoded = $base64Decoded;
                    $encodingFound = 'base64';
                }
            }

            if ($decoded === $current) {
                break;
            }

            $current = $decoded;
            $decodingLayers++;
            $encodingsUsed[] = $encodingFound;
        }

        // Multiple encoding layers is suspicious
        if ($decodingLayers >= 2) {
            return [
                'type' => 'multiple_encoding',
                'severity' => 'high',
                'message' => "Multiple encoding layers detected ({$decodingLayers} layers)",
                'details' => [
                    'layers' => $decodingLayers,
                    'encodings' => $encodingsUsed,
                    'decoded_sample' => substr($current, 0, 100),
                ],
            ];
        }

        return null;
    }

    /**
     * Check for comment injection within payloads.
     */
    private function checkCommentInjection(string $input): ?array
    {
        $commentPatterns = [
            // SQL comments
            '/\/\*.*?\*\//s' => 'SQL block comment',
            '/--[^\r\n]*/' => 'SQL line comment',
            '/#[^\r\n]*/' => 'MySQL comment',
            // HTML/JS comments
            '/<!--.*?-->/s' => 'HTML comment',
            '/\/\/[^\r\n]*/' => 'JS line comment',
            // Null-based splitting
            '/[\'"][^\'"]*\/\*.*?\*\/[^\'"]*[\'"]/s' => 'Comment within string',
        ];

        $found = [];
        foreach ($commentPatterns as $pattern => $name) {
            if (preg_match($pattern, $input)) {
                // Check if it's in a suspicious context (not just legitimate comments)
                if ($this->isCommentSuspicious($input, $pattern)) {
                    $found[] = $name;
                }
            }
        }

        if (!empty($found)) {
            return [
                'type' => 'comment_injection',
                'severity' => 'medium',
                'message' => 'Suspicious comment patterns detected (potential bypass)',
                'details' => [
                    'patterns_found' => $found,
                ],
            ];
        }

        return null;
    }

    /**
     * Check if input contains encoded characters.
     */
    private function containsEncodedChars(string $input, string $type): bool
    {
        return match ($type) {
            'url' => preg_match('/%[0-9A-Fa-f]{2}/', $input) === 1,
            'html' => preg_match('/&(?:#\d+|#x[0-9A-Fa-f]+|\w+);/', $input) === 1,
            default => false,
        };
    }

    /**
     * Check if string looks like base64.
     */
    private function looksLikeBase64(string $input): bool
    {
        $input = trim($input);
        if (strlen($input) < 4 || strlen($input) % 4 !== 0) {
            return false;
        }
        return preg_match('/^[A-Za-z0-9+\/]+=*$/', $input) === 1;
    }

    /**
     * Check if string is printable.
     */
    private function isPrintable(string $input): bool
    {
        return preg_match('/^[\x20-\x7E\s]*$/', $input) === 1;
    }

    /**
     * Check if comment usage is suspicious.
     */
    private function isCommentSuspicious(string $input, string $pattern): bool
    {
        // Comments near SQL keywords are suspicious
        $sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'WHERE', 'OR', 'AND'];
        $inputUpper = strtoupper($input);

        foreach ($sqlKeywords as $keyword) {
            if (strpos($inputUpper, $keyword) !== false) {
                return true;
            }
        }

        return false;
    }

    public function getName(): string
    {
        return 'payload_obfuscation';
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getPriority(): int
    {
        return 97; // Run early to catch obfuscated payloads
    }

    public function getSeverity(): string
    {
        return 'high';
    }
}
