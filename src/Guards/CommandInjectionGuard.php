<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Guards;

use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;

/**
 * Detects potential Command Injection attacks.
 */
class CommandInjectionGuard extends AbstractGuard
{
    /**
     * Quick scan patterns.
     *
     * @var array<string>
     */
    protected array $quickPatterns = ['shell_metacharacters', 'command_substitution'];

    public function getName(): string
    {
        return 'command-injection';
    }

    /**
     * {@inheritdoc}
     */
    protected function getPatterns(): array
    {
        return array_merge($this->getDefaultPatterns(), $this->getConfig('patterns', []));
    }

    /**
     * Default command injection patterns.
     *
     * @return array<string, array<string>>
     */
    protected function getDefaultPatterns(): array
    {
        return [
            'shell_metacharacters' => [
                '[;&|`$]',
                '\|\|',
                '&&',
                '\$\(',
                '`[^`]+`',
            ],

            'command_substitution' => [
                '\$\{[^}]+\}',
                '\$\([^)]+\)',
                '`[^`]+`',
            ],

            'dangerous_commands' => [
                '\b(cat|more|less|head|tail|tac)\s+[/~]',
                '\b(ls|dir|find|locate)\s+',
                '\b(rm|del|rmdir|unlink)\s+',
                '\b(wget|curl|fetch)\s+',
                '\b(nc|netcat|ncat)\s+',
                '\b(bash|sh|zsh|csh|ksh|fish)\s+',
                '\b(python|perl|ruby|php|node)\s+',
                '\b(chmod|chown|chgrp)\s+',
                '\b(useradd|userdel|usermod)\s+',
                '\b(passwd|shadow)\b',
                '\b(crontab|at|batch)\s+',
                '\b(systemctl|service|init)\s+',
                '\b(kill|killall|pkill)\s+',
                '\b(ps|top|htop)\s+',
                '\b(ifconfig|ip|netstat|ss)\s+',
                '\b(iptables|firewall-cmd|ufw)\s+',
            ],

            'path_traversal' => [
                '\.\./\.\.',
                '\.\.\\\\',
                '/etc/passwd',
                '/etc/shadow',
                '/proc/self',
                'C:\\\\Windows',
                '%2e%2e[/\\\\]',
            ],

            'environment_access' => [
                '\$\{?PATH\}?',
                '\$\{?HOME\}?',
                '\$\{?USER\}?',
                '\$\{?SHELL\}?',
                '\$\{?IFS\}?',
                'getenv\s*\(',
                '\$_ENV\[',
                '\$_SERVER\[',
            ],

            'redirection' => [
                '>\s*/dev/',
                '>\s*/tmp/',
                '>\s*/var/',
                '>>\s*[/~]',
                '2>&1',
                '1>&2',
            ],

            'base64_payload' => [
                'base64\s+(-d|--decode)',
                'echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64',
            ],

            'windows_specific' => [
                '\bcmd\s*/c\b',
                '\bpowershell\s+',
                '\bwscript\s+',
                '\bcscript\s+',
                '\bnet\s+(user|localgroup|share)',
                '\breg\s+(query|add|delete)',
                '\bschtasks\s+',
                '\btaskkill\s+',
            ],
        ];
    }

    protected function performInspection(mixed $input, array $context = []): GuardResultInterface
    {
        $normalized = $this->normalizeInput($input);

        if ($normalized === '') {
            return $this->pass();
        }

        // Check for null bytes (common in injection attacks)
        if (str_contains($normalized, "\0") || str_contains($normalized, '%00')) {
            return $this->threat(
                'Null byte injection attempt detected',
                ThreatLevel::CRITICAL,
                ['type' => 'null_byte', 'input_sample' => substr($normalized, 0, 200)]
            );
        }

        // Check all patterns
        foreach ($this->compiledPatterns as $patternName => $pattern) {
            if (preg_match($pattern, $normalized, $matches)) {
                return $this->createInjectionResult($patternName, $matches[0], $normalized);
            }
        }

        // Additional heuristic checks
        if ($this->hasChainedCommands($normalized)) {
            return $this->threat(
                'Command chaining detected',
                ThreatLevel::HIGH,
                ['type' => 'command_chain', 'input_sample' => substr($normalized, 0, 200)]
            );
        }

        if ($this->hasSuspiciousEncoding($normalized)) {
            return $this->threat(
                'Suspicious encoding pattern detected',
                ThreatLevel::MEDIUM,
                ['type' => 'suspicious_encoding', 'input_sample' => substr($normalized, 0, 200)]
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
            return $this->decodeInput($input);
        }

        if (is_array($input)) {
            return $this->decodeInput($this->flattenArray($input));
        }

        return '';
    }

    /**
     * Decode common encodings.
     */
    protected function decodeInput(string $input): string
    {
        // URL decode
        $decoded = urldecode($input);

        // Normalize line endings
        $decoded = str_replace(["\r\n", "\r"], "\n", $decoded);

        return $decoded;
    }

    /**
     * Flatten array to string.
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
     * Check for chained commands.
     */
    protected function hasChainedCommands(string $input): bool
    {
        // Look for patterns like: cmd1 && cmd2, cmd1 || cmd2, cmd1 ; cmd2
        $chainPatterns = [
            '/\w+\s*&&\s*\w+/',
            '/\w+\s*\|\|\s*\w+/',
            '/\w+\s*;\s*\w+/',
            '/\w+\s*\|\s*\w+/',
        ];

        foreach ($chainPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for suspicious encoding patterns.
     */
    protected function hasSuspiciousEncoding(string $input): bool
    {
        // Hex encoding like \x00
        if (preg_match('/\\\\x[0-9a-f]{2}/i', $input)) {
            return true;
        }

        // Octal encoding
        if (preg_match('/\\\\[0-7]{3}/', $input)) {
            return true;
        }

        // Double URL encoding
        if (preg_match('/%25[0-9a-f]{2}/i', $input)) {
            return true;
        }

        return false;
    }

    /**
     * Create injection result.
     */
    protected function createInjectionResult(string $patternName, string $matched, string $fullInput): GuardResultInterface
    {
        $level = match ($patternName) {
            'dangerous_commands', 'command_substitution' => ThreatLevel::CRITICAL,
            'shell_metacharacters', 'path_traversal', 'base64_payload' => ThreatLevel::HIGH,
            'windows_specific', 'redirection' => ThreatLevel::HIGH,
            'environment_access' => ThreatLevel::MEDIUM,
            default => ThreatLevel::MEDIUM,
        };

        return $this->threat(
            "Command injection attempt detected: {$patternName}",
            $level,
            [
                'pattern' => $patternName,
                'matched' => substr($matched, 0, 100),
                'input_sample' => substr($fullInput, 0, 200),
            ]
        );
    }
}
