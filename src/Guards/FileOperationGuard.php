<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardResultInterface;
use M9nx\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Detects dangerous file operations and path traversal attacks.
 */
class FileOperationGuard extends AbstractGuard
{
    /**
     * Quick scan patterns.
     *
     * @var array<string>
     */
    protected array $quickPatterns = ['path_traversal', 'null_byte'];

    /**
     * Allowed base directories.
     *
     * @var array<string>
     */
    protected array $allowedPaths = [];

    /**
     * Dangerous file extensions.
     *
     * @var array<string>
     */
    protected array $dangerousExtensions = [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar',
        'exe', 'bat', 'cmd', 'sh', 'bash', 'ps1',
        'htaccess', 'htpasswd',
        'asp', 'aspx', 'jsp', 'jspx',
        'cgi', 'pl', 'py', 'rb',
    ];

    public function getName(): string
    {
        return 'file-operation';
    }

    /**
     * {@inheritdoc}
     */
    protected function onBoot(): void
    {
        $this->allowedPaths = $this->getConfig('allowed_paths', []);
        $this->dangerousExtensions = $this->getConfig(
            'dangerous_extensions',
            $this->dangerousExtensions
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getPatterns(): array
    {
        return array_merge($this->getDefaultPatterns(), $this->getConfig('patterns', []));
    }

    /**
     * Default file operation patterns.
     *
     * @return array<string, array<string>>
     */
    protected function getDefaultPatterns(): array
    {
        return [
            'path_traversal' => [
                '\.\.[/\\\\]',
                '\.\.%2f',
                '\.\.%5c',
                '%2e%2e[/\\\\]',
                '%252e%252e',
                '\.\.%c0%af',
                '\.\.%c1%9c',
            ],

            'null_byte' => [
                '\x00',
                '%00',
                '\\\\0',
            ],

            'sensitive_files' => [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/hosts',
                '/proc/self',
                '/proc/environ',
                '/var/log/',
                '\.env($|\.)',
                '\.git/',
                '\.svn/',
                'wp-config\.php',
                'config\.php',
                'database\.yml',
                'secrets\.yml',
            ],

            'windows_sensitive' => [
                'C:\\\\Windows\\\\',
                'C:\\\\Users\\\\',
                'C:\\\\Program Files',
                '\\\\boot\.ini',
                '\\\\autoexec\.bat',
                'C:\\\\inetpub',
            ],

            'protocol_wrapper' => [
                'php://input',
                'php://filter',
                'php://data',
                'file://',
                'expect://',
                'phar://',
                'zip://',
                'rar://',
                'compress\.',
                'glob://',
            ],

            'archive_extraction' => [
                '\.\./', // Path in archive
                'symlink',
                'hardlink',
            ],
        ];
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        $normalized = $this->normalizeInput($input);

        if ($normalized === '') {
            return $this->pass();
        }

        // Check for null bytes first (highest priority)
        if ($this->hasNullByte($normalized)) {
            return $this->threat(
                'Null byte injection in file path detected',
                ThreatLevel::CRITICAL,
                ['type' => 'null_byte', 'input_sample' => substr($normalized, 0, 200)]
            );
        }

        // Check all patterns
        foreach ($this->compiledPatterns as $patternName => $pattern) {
            if (preg_match($pattern, $normalized, $matches)) {
                return $this->createFileResult($patternName, $matches[0], $normalized);
            }
        }

        // Check for dangerous extensions in upload context
        if (isset($context['operation']) && $context['operation'] === 'upload') {
            if ($this->hasDangerousExtension($normalized)) {
                return $this->threat(
                    'Dangerous file extension detected',
                    ThreatLevel::HIGH,
                    [
                        'type' => 'dangerous_extension',
                        'extension' => pathinfo($normalized, PATHINFO_EXTENSION),
                    ]
                );
            }
        }

        // Check allowed paths if configured
        if (! empty($this->allowedPaths) && ! $this->isAllowedPath($normalized)) {
            return $this->threat(
                'File access outside allowed directories',
                ThreatLevel::HIGH,
                [
                    'type' => 'path_restriction',
                    'path' => $normalized,
                    'allowed_paths' => $this->allowedPaths,
                ]
            );
        }

        // Detect double extensions
        if ($this->hasDoubleExtension($normalized)) {
            return $this->threat(
                'Double extension attack detected',
                ThreatLevel::HIGH,
                ['type' => 'double_extension', 'filename' => basename($normalized)]
            );
        }

        return $this->pass();
    }

    /**
     * Normalize input.
     */
    protected function normalizeInput(mixed $input): string
    {
        if (is_string($input)) {
            return $this->decodePath($input);
        }

        if (is_array($input)) {
            // Check filename or path keys
            foreach (['filename', 'path', 'file', 'name'] as $key) {
                if (isset($input[$key]) && is_string($input[$key])) {
                    return $this->decodePath($input[$key]);
                }
            }

            return $this->decodePath(json_encode($input) ?: '');
        }

        return '';
    }

    /**
     * Decode path encoding.
     */
    protected function decodePath(string $path): string
    {
        // URL decode multiple times to catch double encoding
        $decoded = $path;
        for ($i = 0; $i < 3; $i++) {
            $newDecoded = urldecode($decoded);
            if ($newDecoded === $decoded) {
                break;
            }
            $decoded = $newDecoded;
        }

        // Normalize directory separators
        $decoded = str_replace('\\', '/', $decoded);

        return $decoded;
    }

    /**
     * Check for null bytes.
     */
    protected function hasNullByte(string $input): bool
    {
        return str_contains($input, "\0") ||
               str_contains($input, '%00') ||
               str_contains($input, "\x00");
    }

    /**
     * Check for dangerous file extensions.
     */
    protected function hasDangerousExtension(string $filename): bool
    {
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        return in_array($extension, $this->dangerousExtensions, true);
    }

    /**
     * Check for double extension attacks (e.g., file.php.jpg).
     */
    protected function hasDoubleExtension(string $filename): bool
    {
        $basename = basename($filename);
        $parts = explode('.', $basename);

        if (count($parts) < 3) {
            return false;
        }

        // Check if any middle part is a dangerous extension
        array_shift($parts); // Remove filename
        array_pop($parts);   // Remove final extension

        foreach ($parts as $part) {
            if (in_array(strtolower($part), $this->dangerousExtensions, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if path is within allowed directories.
     */
    protected function isAllowedPath(string $path): bool
    {
        $realPath = realpath($path);

        if ($realPath === false) {
            // Path doesn't exist yet, check parent
            $realPath = realpath(dirname($path));
            if ($realPath === false) {
                return false;
            }
        }

        foreach ($this->allowedPaths as $allowedPath) {
            $allowedReal = realpath($allowedPath);
            if ($allowedReal !== false && str_starts_with($realPath, $allowedReal)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Create file operation result.
     */
    protected function createFileResult(string $patternName, string $matched, string $fullInput): GuardResultInterface
    {
        $level = match ($patternName) {
            'null_byte', 'protocol_wrapper' => ThreatLevel::CRITICAL,
            'path_traversal', 'sensitive_files', 'windows_sensitive' => ThreatLevel::HIGH,
            'archive_extraction' => ThreatLevel::MEDIUM,
            default => ThreatLevel::MEDIUM,
        };

        return $this->threat(
            "File operation threat detected: {$patternName}",
            $level,
            [
                'pattern' => $patternName,
                'matched' => substr($matched, 0, 100),
                'input_sample' => substr($fullInput, 0, 200),
            ]
        );
    }
}
