<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Guards;

use M9nx\RuntimeGuard\Contracts\GuardInterface;
use M9nx\RuntimeGuard\Context\RuntimeContext;
use M9nx\RuntimeGuard\Results\GuardResult;

/**
 * Bot Behavior Analyzer.
 *
 * Detects automated/bot traffic through:
 * - Request timing patterns
 * - Mouse/keyboard behavior (if available)
 * - Navigation patterns
 * - Honeypot interaction
 * - Browser fingerprint anomalies
 */
class BotBehaviorGuard implements GuardInterface
{
    private bool $enabled;
    private float $requestTimingThreshold;
    private float $navigationAnomalyThreshold;
    private bool $enableHoneypot;
    private array $honeypotFields;
    private array $knownBotSignatures;
    private bool $checkHeadlessIndicators;
    private bool $checkAutomationIndicators;
    private ?object $cache;
    private int $sessionWindow;

    public function __construct(array $config = [])
    {
        $this->enabled = $config['enabled'] ?? true;
        $this->requestTimingThreshold = $config['request_timing_threshold'] ?? 0.1; // 100ms
        $this->navigationAnomalyThreshold = $config['navigation_anomaly_threshold'] ?? 0.8;
        $this->enableHoneypot = $config['enable_honeypot'] ?? true;
        $this->honeypotFields = $config['honeypot_fields'] ?? ['website', 'url', 'email_confirm', '_honey', 'fax'];
        $this->knownBotSignatures = $config['known_bot_signatures'] ?? [];
        $this->checkHeadlessIndicators = $config['check_headless_indicators'] ?? true;
        $this->checkAutomationIndicators = $config['check_automation_indicators'] ?? true;
        $this->cache = $config['cache'] ?? null;
        $this->sessionWindow = $config['session_window'] ?? 3600;
    }

    public function inspect(RuntimeContext $context): GuardResult
    {
        if (!$this->enabled) {
            return GuardResult::pass($this->getName());
        }

        $request = $context->getRequest();
        $threats = [];
        $metadata = [];
        $botScore = 0.0;

        // Check 1: User-Agent analysis
        $uaResult = $this->analyzeUserAgent($request);
        $botScore += $uaResult['score'];
        if ($uaResult['threat']) {
            $threats[] = $uaResult['threat'];
        }
        $metadata['user_agent_analysis'] = $uaResult;

        // Check 2: Request timing patterns
        $timingResult = $this->analyzeRequestTiming($request);
        $botScore += $timingResult['score'];
        if ($timingResult['threat']) {
            $threats[] = $timingResult['threat'];
        }
        $metadata['timing_analysis'] = $timingResult;

        // Check 3: Honeypot fields
        if ($this->enableHoneypot) {
            $honeypotResult = $this->checkHoneypot($request);
            if ($honeypotResult['triggered']) {
                $botScore += 0.9; // Strong signal
                $threats[] = $honeypotResult['threat'];
            }
            $metadata['honeypot_check'] = $honeypotResult;
        }

        // Check 4: Navigation patterns
        $navResult = $this->analyzeNavigationPatterns($request);
        $botScore += $navResult['score'];
        if ($navResult['threat']) {
            $threats[] = $navResult['threat'];
        }
        $metadata['navigation_analysis'] = $navResult;

        // Check 5: Browser fingerprint anomalies
        $fpResult = $this->analyzeBrowserFingerprint($request);
        $botScore += $fpResult['score'];
        if ($fpResult['threat']) {
            $threats[] = $fpResult['threat'];
        }
        $metadata['fingerprint_analysis'] = $fpResult;

        // Check 6: Headless browser indicators
        if ($this->checkHeadlessIndicators) {
            $headlessResult = $this->detectHeadlessBrowser($request);
            $botScore += $headlessResult['score'];
            if ($headlessResult['threat']) {
                $threats[] = $headlessResult['threat'];
            }
            $metadata['headless_detection'] = $headlessResult;
        }

        // Check 7: Automation framework indicators
        if ($this->checkAutomationIndicators) {
            $automationResult = $this->detectAutomationFramework($request);
            $botScore += $automationResult['score'];
            if ($automationResult['threat']) {
                $threats[] = $automationResult['threat'];
            }
            $metadata['automation_detection'] = $automationResult;
        }

        // Normalize score
        $normalizedScore = min(1.0, $botScore);
        $metadata['bot_score'] = $normalizedScore;
        $metadata['bot_likelihood'] = $this->scoreToBotLikelihood($normalizedScore);

        // Record session behavior
        $this->recordSessionBehavior($request, $normalizedScore);

        if (!empty($threats)) {
            return GuardResult::fail($this->getName(), $threats)
                ->withMetadata($metadata);
        }

        return GuardResult::pass($this->getName())
            ->withMetadata($metadata);
    }

    /**
     * Analyze User-Agent for bot indicators.
     */
    private function analyzeUserAgent(object $request): array
    {
        $ua = $request->userAgent() ?? '';
        $score = 0.0;
        $indicators = [];

        if (empty($ua)) {
            return [
                'score' => 0.3,
                'indicators' => ['empty_user_agent'],
                'threat' => [
                    'type' => 'bot_empty_user_agent',
                    'severity' => 'medium',
                    'message' => 'Request has empty User-Agent',
                ],
            ];
        }

        // Known bot signatures
        $botPatterns = array_merge($this->knownBotSignatures, [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests',
            'httpx', 'axios', 'fetch', 'go-http-client', 'java/', 'okhttp',
            'libwww', 'httpclient', 'apache-httpclient', 'scrapy', 'phantomjs',
            'headlesschrome', 'puppeteer', 'playwright', 'selenium', 'webdriver',
        ]);

        $uaLower = strtolower($ua);
        foreach ($botPatterns as $pattern) {
            if (str_contains($uaLower, strtolower($pattern))) {
                $score += 0.5;
                $indicators[] = "matches_pattern:{$pattern}";
            }
        }

        // Check for obviously fake browsers
        if (preg_match('/Chrome\/(\d+)/', $ua, $matches)) {
            $version = (int) $matches[1];
            // Very old or impossibly new Chrome
            if ($version < 70 || $version > 200) {
                $score += 0.2;
                $indicators[] = 'suspicious_chrome_version';
            }
        }

        // Check for missing expected headers with browser UA
        if (str_contains($uaLower, 'mozilla')) {
            if (!$request->header('Accept-Language')) {
                $score += 0.1;
                $indicators[] = 'missing_accept_language';
            }
            if (!$request->header('Accept-Encoding')) {
                $score += 0.1;
                $indicators[] = 'missing_accept_encoding';
            }
        }

        $threat = null;
        if ($score >= 0.3) {
            $threat = [
                'type' => 'bot_user_agent_suspicious',
                'severity' => $score >= 0.5 ? 'high' : 'medium',
                'message' => 'User-Agent shows bot-like characteristics',
                'details' => ['indicators' => $indicators],
            ];
        }

        return [
            'score' => $score,
            'indicators' => $indicators,
            'threat' => $threat,
        ];
    }

    /**
     * Analyze request timing patterns.
     */
    private function analyzeRequestTiming(object $request): array
    {
        if (!$this->cache) {
            return ['score' => 0, 'threat' => null];
        }

        $ip = $request->ip();
        $key = "bot_timing:{$ip}";
        $timestamps = $this->cache->get($key, []);

        $now = microtime(true);
        $timestamps[] = $now;

        // Keep last 20 timestamps
        $timestamps = array_slice($timestamps, -20);
        $this->cache->put($key, $timestamps, $this->sessionWindow);

        if (count($timestamps) < 3) {
            return ['score' => 0, 'threat' => null];
        }

        // Calculate intervals
        $intervals = [];
        for ($i = 1; $i < count($timestamps); $i++) {
            $intervals[] = $timestamps[$i] - $timestamps[$i - 1];
        }

        // Check for suspiciously consistent timing
        $mean = array_sum($intervals) / count($intervals);
        $variance = 0;
        foreach ($intervals as $interval) {
            $variance += pow($interval - $mean, 2);
        }
        $variance /= count($intervals);
        $stdDev = sqrt($variance);

        // Coefficient of variation - very low = suspiciously consistent
        $cv = $mean > 0 ? $stdDev / $mean : 0;

        $score = 0;
        $indicators = [];

        // Very consistent timing (CV < 0.1) is suspicious
        if ($cv < 0.1 && count($intervals) >= 5) {
            $score = 0.4;
            $indicators[] = 'consistent_timing';
        }

        // Very fast requests
        if ($mean < $this->requestTimingThreshold) {
            $score += 0.3;
            $indicators[] = 'rapid_requests';
        }

        $threat = null;
        if ($score >= 0.3) {
            $threat = [
                'type' => 'bot_timing_pattern',
                'severity' => 'medium',
                'message' => 'Request timing suggests automated behavior',
                'details' => [
                    'mean_interval' => round($mean * 1000, 2) . 'ms',
                    'cv' => round($cv, 3),
                ],
            ];
        }

        return [
            'score' => $score,
            'indicators' => $indicators,
            'mean_interval_ms' => round($mean * 1000, 2),
            'cv' => round($cv, 3),
            'threat' => $threat,
        ];
    }

    /**
     * Check honeypot fields.
     */
    private function checkHoneypot(object $request): array
    {
        if ($request->method() !== 'POST') {
            return ['triggered' => false, 'field' => null, 'threat' => null];
        }

        foreach ($this->honeypotFields as $field) {
            $value = $request->input($field);
            if ($value !== null && $value !== '') {
                return [
                    'triggered' => true,
                    'field' => $field,
                    'threat' => [
                        'type' => 'bot_honeypot_triggered',
                        'severity' => 'high',
                        'message' => 'Bot detected via honeypot field',
                        'details' => ['field' => $field],
                    ],
                ];
            }
        }

        return ['triggered' => false, 'field' => null, 'threat' => null];
    }

    /**
     * Analyze navigation patterns.
     */
    private function analyzeNavigationPatterns(object $request): array
    {
        if (!$this->cache) {
            return ['score' => 0, 'threat' => null];
        }

        $ip = $request->ip();
        $key = "bot_nav:{$ip}";
        $history = $this->cache->get($key, []);

        $currentPath = $request->path();
        $referer = $request->header('Referer');

        $history[] = [
            'path' => $currentPath,
            'referer' => $referer,
            'time' => time(),
        ];

        // Keep last 50 requests
        $history = array_slice($history, -50);
        $this->cache->put($key, $history, $this->sessionWindow);

        if (count($history) < 5) {
            return ['score' => 0, 'threat' => null];
        }

        $score = 0;
        $indicators = [];

        // Check for missing referers (bots often don't set them)
        $missingReferers = 0;
        foreach ($history as $entry) {
            if (empty($entry['referer'])) {
                $missingReferers++;
            }
        }

        $missingRefererRatio = $missingReferers / count($history);
        if ($missingRefererRatio > 0.8) {
            $score += 0.2;
            $indicators[] = 'missing_referers';
        }

        // Check for unnatural navigation (hitting deep pages directly)
        $directDeepPages = 0;
        foreach ($history as $entry) {
            $depth = substr_count($entry['path'], '/');
            if ($depth >= 3 && empty($entry['referer'])) {
                $directDeepPages++;
            }
        }

        if ($directDeepPages > count($history) * 0.5) {
            $score += 0.2;
            $indicators[] = 'direct_deep_navigation';
        }

        $threat = null;
        if ($score >= $this->navigationAnomalyThreshold * 0.3) {
            $threat = [
                'type' => 'bot_navigation_anomaly',
                'severity' => 'low',
                'message' => 'Navigation pattern suggests automated behavior',
                'details' => ['indicators' => $indicators],
            ];
        }

        return [
            'score' => $score,
            'indicators' => $indicators,
            'threat' => $threat,
        ];
    }

    /**
     * Analyze browser fingerprint for anomalies.
     */
    private function analyzeBrowserFingerprint(object $request): array
    {
        $score = 0;
        $indicators = [];

        // Check for inconsistencies
        $ua = strtolower($request->userAgent() ?? '');
        $acceptLanguage = $request->header('Accept-Language', '');
        $acceptEncoding = $request->header('Accept-Encoding', '');

        // Chrome should support br encoding
        if (str_contains($ua, 'chrome') && !str_contains(strtolower($acceptEncoding), 'br')) {
            $score += 0.1;
            $indicators[] = 'chrome_missing_brotli';
        }

        // Mobile UA with desktop indicators
        if (str_contains($ua, 'mobile') || str_contains($ua, 'android')) {
            $screenWidth = $request->header('Sec-CH-UA-Mobile');
            // Could add more checks if client hints are available
        }

        // Check for DNT header with privacy browsers
        $dnt = $request->header('DNT');
        $secGpc = $request->header('Sec-GPC');

        $threat = null;
        if ($score >= 0.2) {
            $threat = [
                'type' => 'bot_fingerprint_anomaly',
                'severity' => 'low',
                'message' => 'Browser fingerprint shows anomalies',
                'details' => ['indicators' => $indicators],
            ];
        }

        return [
            'score' => $score,
            'indicators' => $indicators,
            'threat' => $threat,
        ];
    }

    /**
     * Detect headless browser indicators.
     */
    private function detectHeadlessBrowser(object $request): array
    {
        $ua = strtolower($request->userAgent() ?? '');
        $indicators = [];
        $score = 0;

        // Direct headless indicators
        $headlessPatterns = ['headless', 'phantomjs', 'slimerjs', 'zombie'];
        foreach ($headlessPatterns as $pattern) {
            if (str_contains($ua, $pattern)) {
                $score += 0.6;
                $indicators[] = "ua_contains:{$pattern}";
            }
        }

        // Chrome headless often has different window dimensions header
        if (str_contains($ua, 'chrome') && str_contains($ua, 'headlesschrome')) {
            $score += 0.7;
            $indicators[] = 'headlesschrome_in_ua';
        }

        $threat = null;
        if ($score > 0) {
            $threat = [
                'type' => 'bot_headless_browser',
                'severity' => 'high',
                'message' => 'Headless browser detected',
                'details' => ['indicators' => $indicators],
            ];
        }

        return [
            'score' => $score,
            'indicators' => $indicators,
            'threat' => $threat,
        ];
    }

    /**
     * Detect automation framework indicators.
     */
    private function detectAutomationFramework(object $request): array
    {
        $ua = strtolower($request->userAgent() ?? '');
        $indicators = [];
        $score = 0;

        // Selenium/WebDriver indicators
        $automationPatterns = [
            'selenium', 'webdriver', 'puppeteer', 'playwright',
            'cypress', 'protractor', 'nightwatch',
        ];

        foreach ($automationPatterns as $pattern) {
            if (str_contains($ua, $pattern)) {
                $score += 0.8;
                $indicators[] = "automation:{$pattern}";
            }
        }

        // Check for WebDriver-specific headers
        // (Some automation tools add custom headers)

        $threat = null;
        if ($score > 0) {
            $threat = [
                'type' => 'bot_automation_framework',
                'severity' => 'high',
                'message' => 'Automation framework detected',
                'details' => ['indicators' => $indicators],
            ];
        }

        return [
            'score' => $score,
            'indicators' => $indicators,
            'threat' => $threat,
        ];
    }

    /**
     * Convert score to likelihood label.
     */
    private function scoreToBotLikelihood(float $score): string
    {
        if ($score >= 0.8) return 'very_likely_bot';
        if ($score >= 0.6) return 'likely_bot';
        if ($score >= 0.4) return 'possibly_bot';
        if ($score >= 0.2) return 'unlikely_bot';
        return 'likely_human';
    }

    /**
     * Record session behavior for analysis.
     */
    private function recordSessionBehavior(object $request, float $score): void
    {
        if (!$this->cache) {
            return;
        }

        $ip = $request->ip();
        $key = "bot_scores:{$ip}";
        $scores = $this->cache->get($key, []);
        $scores[] = $score;
        $scores = array_slice($scores, -100);
        $this->cache->put($key, $scores, $this->sessionWindow);
    }

    public function getName(): string
    {
        return 'bot_behavior';
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function getPriority(): int
    {
        return 30;
    }

    public function getSeverity(): string
    {
        return 'medium';
    }
}
