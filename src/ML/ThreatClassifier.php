<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\ML;

use Illuminate\Support\Facades\Cache;

/**
 * Threat Classifier.
 *
 * Classifies security threats using ML techniques:
 * - Multi-class threat classification
 * - Confidence scoring
 * - Feature importance analysis
 * - Naive Bayes classification
 */
class ThreatClassifier
{
    private array $config;
    private array $classes;
    private float $confidenceThreshold;
    private string $cachePrefix;
    private array $featureImportance;

    // Threat categories
    public const CLASS_INJECTION = 'injection';
    public const CLASS_XSS = 'xss';
    public const CLASS_BRUTE_FORCE = 'brute_force';
    public const CLASS_ENUMERATION = 'enumeration';
    public const CLASS_BOT = 'bot';
    public const CLASS_DOS = 'dos';
    public const CLASS_CREDENTIAL_STUFFING = 'credential_stuffing';
    public const CLASS_SESSION_HIJACK = 'session_hijack';
    public const CLASS_API_ABUSE = 'api_abuse';
    public const CLASS_DATA_EXFILTRATION = 'data_exfiltration';
    public const CLASS_BENIGN = 'benign';

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->confidenceThreshold = $config['confidence_threshold'] ?? 0.6;
        $this->cachePrefix = $config['cache_prefix'] ?? 'threat_classifier:';

        $this->classes = [
            self::CLASS_INJECTION,
            self::CLASS_XSS,
            self::CLASS_BRUTE_FORCE,
            self::CLASS_ENUMERATION,
            self::CLASS_BOT,
            self::CLASS_DOS,
            self::CLASS_CREDENTIAL_STUFFING,
            self::CLASS_SESSION_HIJACK,
            self::CLASS_API_ABUSE,
            self::CLASS_DATA_EXFILTRATION,
            self::CLASS_BENIGN,
        ];

        $this->featureImportance = $config['feature_importance'] ?? [
            'has_sql_keywords' => 0.9,
            'has_script_tags' => 0.85,
            'request_rate' => 0.7,
            'unique_ips' => 0.6,
            'failed_auth_rate' => 0.8,
            'payload_entropy' => 0.65,
            'response_time_variance' => 0.5,
            'sequential_ids' => 0.75,
            'user_agent_anomaly' => 0.7,
            'session_anomaly' => 0.8,
        ];
    }

    /**
     * Classify a request/event.
     */
    public function classify(array $features): ClassificationResult
    {
        $model = $this->getModel();

        // Calculate class probabilities using Naive Bayes
        $probabilities = $this->calculateProbabilities($features, $model);

        // Apply feature-based rules
        $ruleScores = $this->applyRules($features);

        // Combine probabilistic and rule-based scores
        $combinedScores = $this->combineScores($probabilities, $ruleScores);

        // Get top class
        arsort($combinedScores);
        $predictedClass = key($combinedScores);
        $confidence = current($combinedScores);

        // Determine severity
        $severity = $this->determineSeverity($predictedClass, $confidence);

        // Get important features
        $importantFeatures = $this->getImportantFeatures($features, $predictedClass);

        return new ClassificationResult(
            $predictedClass,
            $confidence,
            $combinedScores,
            $severity,
            $importantFeatures
        );
    }

    /**
     * Train the classifier with labeled data.
     */
    public function train(array $samples): void
    {
        $model = [
            'class_priors' => [],
            'feature_likelihoods' => [],
            'feature_means' => [],
            'feature_variances' => [],
            'total_samples' => 0,
        ];

        // Calculate class priors
        $classCounts = [];
        foreach ($samples as $sample) {
            $class = $sample['class'];
            $classCounts[$class] = ($classCounts[$class] ?? 0) + 1;
        }

        $total = count($samples);
        foreach ($classCounts as $class => $count) {
            $model['class_priors'][$class] = $count / $total;
        }

        // Calculate feature statistics per class
        $featuresByClass = [];
        foreach ($samples as $sample) {
            $class = $sample['class'];
            $features = $sample['features'] ?? [];

            if (!isset($featuresByClass[$class])) {
                $featuresByClass[$class] = [];
            }

            foreach ($features as $feature => $value) {
                if (!isset($featuresByClass[$class][$feature])) {
                    $featuresByClass[$class][$feature] = [];
                }
                $featuresByClass[$class][$feature][] = $value;
            }
        }

        // Calculate means and variances
        foreach ($featuresByClass as $class => $features) {
            foreach ($features as $feature => $values) {
                if (!empty($values)) {
                    $numericValues = array_filter($values, 'is_numeric');
                    if (!empty($numericValues)) {
                        $mean = array_sum($numericValues) / count($numericValues);
                        $variance = $this->calculateVariance($numericValues, $mean);

                        $model['feature_means'][$class][$feature] = $mean;
                        $model['feature_variances'][$class][$feature] = max($variance, 0.001); // Avoid zero variance
                    } else {
                        // For categorical features, calculate frequencies
                        $model['feature_likelihoods'][$class][$feature] = array_count_values($values);
                    }
                }
            }
        }

        $model['total_samples'] = $total;
        $this->saveModel($model);
    }

    /**
     * Calculate class probabilities using Naive Bayes.
     */
    private function calculateProbabilities(array $features, array $model): array
    {
        if (empty($model['class_priors'])) {
            // No trained model, return uniform distribution
            $uniform = 1 / count($this->classes);
            return array_fill_keys($this->classes, $uniform);
        }

        $logProbabilities = [];

        foreach ($this->classes as $class) {
            // Start with log prior
            $logProb = log($model['class_priors'][$class] ?? (1 / count($this->classes)));

            foreach ($features as $feature => $value) {
                if (is_numeric($value)) {
                    // Gaussian likelihood for numeric features
                    $mean = $model['feature_means'][$class][$feature] ?? 0;
                    $variance = $model['feature_variances'][$class][$feature] ?? 1;

                    $logLikelihood = $this->gaussianLogLikelihood($value, $mean, $variance);
                    $logProb += $logLikelihood;
                } else {
                    // Categorical likelihood
                    $frequencies = $model['feature_likelihoods'][$class][$feature] ?? [];
                    $total = array_sum($frequencies);
                    $count = $frequencies[$value] ?? 0;

                    // Laplace smoothing
                    $likelihood = ($count + 1) / ($total + count($frequencies) + 1);
                    $logProb += log($likelihood);
                }
            }

            $logProbabilities[$class] = $logProb;
        }

        // Convert to probabilities using softmax
        return $this->softmax($logProbabilities);
    }

    /**
     * Apply rule-based scoring.
     */
    private function applyRules(array $features): array
    {
        $scores = array_fill_keys($this->classes, 0.0);

        // Injection indicators
        if ($features['has_sql_keywords'] ?? false) {
            $scores[self::CLASS_INJECTION] += 0.8;
        }
        if (($features['quote_count'] ?? 0) > 3) {
            $scores[self::CLASS_INJECTION] += 0.3;
        }
        if ($features['has_union_select'] ?? false) {
            $scores[self::CLASS_INJECTION] += 0.9;
        }

        // XSS indicators
        if ($features['has_script_tags'] ?? false) {
            $scores[self::CLASS_XSS] += 0.9;
        }
        if ($features['has_event_handlers'] ?? false) {
            $scores[self::CLASS_XSS] += 0.7;
        }
        if ($features['has_javascript_uri'] ?? false) {
            $scores[self::CLASS_XSS] += 0.8;
        }

        // Brute force indicators
        if (($features['failed_auth_rate'] ?? 0) > 0.5) {
            $scores[self::CLASS_BRUTE_FORCE] += 0.7;
        }
        if (($features['request_rate'] ?? 0) > 10) {
            $scores[self::CLASS_BRUTE_FORCE] += 0.4;
        }

        // Enumeration indicators
        if ($features['sequential_ids'] ?? false) {
            $scores[self::CLASS_ENUMERATION] += 0.8;
        }
        if (($features['unique_endpoints'] ?? 0) > 50) {
            $scores[self::CLASS_ENUMERATION] += 0.5;
        }

        // Bot indicators
        if ($features['user_agent_anomaly'] ?? false) {
            $scores[self::CLASS_BOT] += 0.6;
        }
        if ($features['missing_headers'] ?? false) {
            $scores[self::CLASS_BOT] += 0.4;
        }
        if ($features['perfect_timing'] ?? false) {
            $scores[self::CLASS_BOT] += 0.7;
        }

        // DoS indicators
        if (($features['request_rate'] ?? 0) > 100) {
            $scores[self::CLASS_DOS] += 0.8;
        }
        if (($features['payload_size'] ?? 0) > 1000000) {
            $scores[self::CLASS_DOS] += 0.6;
        }

        // Credential stuffing indicators
        if (($features['unique_credentials'] ?? 0) > 10) {
            $scores[self::CLASS_CREDENTIAL_STUFFING] += 0.7;
        }
        if ($features['known_breach_pattern'] ?? false) {
            $scores[self::CLASS_CREDENTIAL_STUFFING] += 0.9;
        }

        // Session hijack indicators
        if ($features['session_anomaly'] ?? false) {
            $scores[self::CLASS_SESSION_HIJACK] += 0.8;
        }
        if ($features['ip_change'] ?? false) {
            $scores[self::CLASS_SESSION_HIJACK] += 0.5;
        }

        // API abuse indicators
        if (($features['graphql_depth'] ?? 0) > 7) {
            $scores[self::CLASS_API_ABUSE] += 0.7;
        }
        if ($features['parameter_pollution'] ?? false) {
            $scores[self::CLASS_API_ABUSE] += 0.6;
        }

        // Data exfiltration indicators
        if (($features['response_size'] ?? 0) > 5000000) {
            $scores[self::CLASS_DATA_EXFILTRATION] += 0.5;
        }
        if (($features['sensitive_data_access'] ?? 0) > 10) {
            $scores[self::CLASS_DATA_EXFILTRATION] += 0.7;
        }

        // Benign baseline
        if (max($scores) < 0.3) {
            $scores[self::CLASS_BENIGN] = 0.8;
        }

        // Normalize scores
        $total = array_sum($scores);
        if ($total > 0) {
            foreach ($scores as $class => $score) {
                $scores[$class] = $score / $total;
            }
        }

        return $scores;
    }

    /**
     * Combine probabilistic and rule-based scores.
     */
    private function combineScores(array $probabilities, array $ruleScores): array
    {
        $combined = [];
        $probWeight = 0.4;
        $ruleWeight = 0.6;

        foreach ($this->classes as $class) {
            $prob = $probabilities[$class] ?? 0;
            $rule = $ruleScores[$class] ?? 0;
            $combined[$class] = ($prob * $probWeight) + ($rule * $ruleWeight);
        }

        // Normalize
        $total = array_sum($combined);
        if ($total > 0) {
            foreach ($combined as $class => $score) {
                $combined[$class] = $score / $total;
            }
        }

        return $combined;
    }

    /**
     * Determine threat severity.
     */
    private function determineSeverity(string $class, float $confidence): string
    {
        $baseSeverity = match ($class) {
            self::CLASS_INJECTION, self::CLASS_DATA_EXFILTRATION => 'critical',
            self::CLASS_XSS, self::CLASS_CREDENTIAL_STUFFING, self::CLASS_SESSION_HIJACK => 'high',
            self::CLASS_BRUTE_FORCE, self::CLASS_DOS, self::CLASS_API_ABUSE => 'medium',
            self::CLASS_ENUMERATION, self::CLASS_BOT => 'low',
            self::CLASS_BENIGN => 'info',
            default => 'medium',
        };

        // Adjust based on confidence
        if ($confidence < 0.5 && $baseSeverity !== 'info') {
            return match ($baseSeverity) {
                'critical' => 'high',
                'high' => 'medium',
                'medium' => 'low',
                default => 'info',
            };
        }

        return $baseSeverity;
    }

    /**
     * Get important features for classification.
     */
    private function getImportantFeatures(array $features, string $class): array
    {
        $important = [];

        foreach ($features as $feature => $value) {
            $importance = $this->featureImportance[$feature] ?? 0.5;

            // Only include features that contributed significantly
            if ($importance > 0.5 && $value) {
                $important[$feature] = [
                    'value' => $value,
                    'importance' => $importance,
                ];
            }
        }

        // Sort by importance
        uasort($important, fn($a, $b) => $b['importance'] <=> $a['importance']);

        return array_slice($important, 0, 5, true);
    }

    /**
     * Calculate Gaussian log likelihood.
     */
    private function gaussianLogLikelihood(float $x, float $mean, float $variance): float
    {
        $diff = $x - $mean;
        return -0.5 * (log(2 * M_PI * $variance) + ($diff * $diff / $variance));
    }

    /**
     * Softmax function.
     */
    private function softmax(array $logits): array
    {
        $maxLogit = max($logits);
        $expSum = 0;

        foreach ($logits as $logit) {
            $expSum += exp($logit - $maxLogit);
        }

        $result = [];
        foreach ($logits as $class => $logit) {
            $result[$class] = exp($logit - $maxLogit) / $expSum;
        }

        return $result;
    }

    /**
     * Calculate variance.
     */
    private function calculateVariance(array $values, float $mean): float
    {
        $squaredDiffs = array_map(fn($v) => pow($v - $mean, 2), $values);
        return array_sum($squaredDiffs) / count($squaredDiffs);
    }

    /**
     * Get trained model.
     */
    private function getModel(): array
    {
        return Cache::get($this->cachePrefix . 'model', []);
    }

    /**
     * Save trained model.
     */
    private function saveModel(array $model): void
    {
        Cache::put($this->cachePrefix . 'model', $model, 86400 * 30);
    }

    /**
     * Extract features from request for classification.
     */
    public function extractFeatures(object $request, array $context = []): array
    {
        $content = $request->getContent() ?? '';
        $query = http_build_query($request->query() ?? []);
        $combinedInput = $content . $query;

        return [
            // Injection indicators
            'has_sql_keywords' => (bool)preg_match('/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b/i', $combinedInput),
            'has_union_select' => (bool)preg_match('/UNION\s+SELECT/i', $combinedInput),
            'quote_count' => substr_count($combinedInput, "'") + substr_count($combinedInput, '"'),

            // XSS indicators
            'has_script_tags' => (bool)preg_match('/<script/i', $combinedInput),
            'has_event_handlers' => (bool)preg_match('/\bon\w+\s*=/i', $combinedInput),
            'has_javascript_uri' => (bool)preg_match('/javascript:/i', $combinedInput),

            // Request characteristics
            'request_rate' => $context['request_rate'] ?? 0,
            'failed_auth_rate' => $context['failed_auth_rate'] ?? 0,
            'payload_size' => strlen($content),
            'response_size' => $context['response_size'] ?? 0,

            // User characteristics
            'user_agent_anomaly' => $context['user_agent_anomaly'] ?? false,
            'missing_headers' => empty($request->header('Accept')),
            'perfect_timing' => $context['perfect_timing'] ?? false,
            'ip_change' => $context['ip_change'] ?? false,

            // API characteristics
            'graphql_depth' => $context['graphql_depth'] ?? 0,
            'parameter_pollution' => $context['parameter_pollution'] ?? false,
            'sequential_ids' => $context['sequential_ids'] ?? false,
            'unique_endpoints' => $context['unique_endpoints'] ?? 0,

            // Auth characteristics
            'unique_credentials' => $context['unique_credentials'] ?? 0,
            'session_anomaly' => $context['session_anomaly'] ?? false,
            'sensitive_data_access' => $context['sensitive_data_access'] ?? 0,
        ];
    }

    /**
     * Get classification classes.
     */
    public function getClasses(): array
    {
        return $this->classes;
    }
}

/**
 * Classification result.
 */
class ClassificationResult
{
    public function __construct(
        public readonly string $predictedClass,
        public readonly float $confidence,
        public readonly array $allScores,
        public readonly string $severity,
        public readonly array $importantFeatures
    ) {}

    public function isThreat(): bool
    {
        return $this->predictedClass !== ThreatClassifier::CLASS_BENIGN
            && $this->confidence >= 0.5;
    }

    public function toArray(): array
    {
        return [
            'predicted_class' => $this->predictedClass,
            'confidence' => round($this->confidence, 4),
            'severity' => $this->severity,
            'is_threat' => $this->isThreat(),
            'all_scores' => array_map(fn($s) => round($s, 4), $this->allScores),
            'important_features' => $this->importantFeatures,
        ];
    }
}
