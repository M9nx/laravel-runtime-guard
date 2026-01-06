<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Performance;

use Mounir\RuntimeGuard\Context\RuntimeContext;
use Illuminate\Support\Facades\Cache;

/**
 * Incremental Inspector.
 *
 * Performs incremental security inspection:
 * - Progressive payload analysis
 * - Early termination on threat detection
 * - Checkpoint-based processing
 * - Memory-efficient streaming analysis
 */
class IncrementalInspector
{
    private array $config;
    private int $chunkSize;
    private int $maxChunks;
    private float $earlyTerminationThreshold;
    private array $inspectors;

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->chunkSize = $config['chunk_size'] ?? 4096;
        $this->maxChunks = $config['max_chunks'] ?? 256;
        $this->earlyTerminationThreshold = $config['early_termination_threshold'] ?? 0.8;

        $this->inspectors = [
            'sql_injection' => $this->createSqlInspector(),
            'xss' => $this->createXssInspector(),
            'path_traversal' => $this->createPathTraversalInspector(),
            'command_injection' => $this->createCommandInjectionInspector(),
            'entropy' => $this->createEntropyInspector(),
        ];
    }

    /**
     * Inspect content incrementally.
     */
    public function inspect(string $content, array $inspectorNames = []): IncrementalResult
    {
        $activeInspectors = empty($inspectorNames)
            ? $this->inspectors
            : array_intersect_key($this->inspectors, array_flip($inspectorNames));

        $state = new InspectionState($activeInspectors);
        $chunks = str_split($content, $this->chunkSize);
        $processedChunks = 0;
        $totalChunks = min(count($chunks), $this->maxChunks);

        foreach ($chunks as $index => $chunk) {
            if ($index >= $this->maxChunks) {
                break;
            }

            $state = $this->processChunk($chunk, $index, $state);
            $processedChunks++;

            // Check for early termination
            if ($this->shouldTerminate($state)) {
                break;
            }
        }

        return $this->createResult($state, $processedChunks, $totalChunks, strlen($content));
    }

    /**
     * Inspect stream incrementally.
     */
    public function inspectStream($stream, array $inspectorNames = []): IncrementalResult
    {
        $activeInspectors = empty($inspectorNames)
            ? $this->inspectors
            : array_intersect_key($this->inspectors, array_flip($inspectorNames));

        $state = new InspectionState($activeInspectors);
        $processedChunks = 0;
        $totalBytes = 0;

        while (!feof($stream) && $processedChunks < $this->maxChunks) {
            $chunk = fread($stream, $this->chunkSize);
            if ($chunk === false || $chunk === '') {
                break;
            }

            $totalBytes += strlen($chunk);
            $state = $this->processChunk($chunk, $processedChunks, $state);
            $processedChunks++;

            if ($this->shouldTerminate($state)) {
                break;
            }
        }

        return $this->createResult($state, $processedChunks, $processedChunks, $totalBytes);
    }

    /**
     * Create checkpoint for resumable inspection.
     */
    public function createCheckpoint(
        string $content,
        array $inspectorNames = []
    ): InspectionCheckpoint {
        $id = uniqid('insp_', true);
        $activeInspectors = empty($inspectorNames)
            ? $this->inspectors
            : array_intersect_key($this->inspectors, array_flip($inspectorNames));

        $checkpoint = new InspectionCheckpoint(
            $id,
            $content,
            0,
            new InspectionState($activeInspectors)
        );

        Cache::put("incremental_inspector:checkpoint:{$id}", $checkpoint, 300);

        return $checkpoint;
    }

    /**
     * Resume inspection from checkpoint.
     */
    public function resumeFromCheckpoint(
        string $checkpointId,
        int $maxChunks = null
    ): IncrementalResult {
        $checkpoint = Cache::get("incremental_inspector:checkpoint:{$checkpointId}");

        if (!$checkpoint) {
            throw new \RuntimeException("Checkpoint not found: {$checkpointId}");
        }

        $content = $checkpoint->content;
        $chunks = str_split($content, $this->chunkSize);
        $startIndex = $checkpoint->processedChunks;
        $state = $checkpoint->state;
        $processedChunks = $startIndex;
        $maxToProcess = $maxChunks ?? ($this->maxChunks - $startIndex);

        for ($i = $startIndex; $i < count($chunks) && $i < $startIndex + $maxToProcess; $i++) {
            $state = $this->processChunk($chunks[$i], $i, $state);
            $processedChunks++;

            if ($this->shouldTerminate($state)) {
                break;
            }
        }

        // Update checkpoint
        $checkpoint = $checkpoint->withProgress($processedChunks, $state);
        Cache::put("incremental_inspector:checkpoint:{$checkpointId}", $checkpoint, 300);

        $isComplete = $processedChunks >= count($chunks) || $this->shouldTerminate($state);

        if ($isComplete) {
            Cache::forget("incremental_inspector:checkpoint:{$checkpointId}");
        }

        return $this->createResult(
            $state,
            $processedChunks,
            count($chunks),
            strlen($content),
            !$isComplete ? $checkpointId : null
        );
    }

    /**
     * Process a single chunk.
     */
    private function processChunk(string $chunk, int $index, InspectionState $state): InspectionState
    {
        foreach ($state->inspectors as $name => $inspector) {
            if ($state->isInspectorTerminated($name)) {
                continue;
            }

            $result = $inspector($chunk, $state->getInspectorState($name), $index);

            $state = $state->updateInspector(
                $name,
                $result['state'],
                $result['score'],
                $result['findings'] ?? []
            );

            // Mark inspector as terminated if score exceeds threshold
            if ($result['score'] >= $this->earlyTerminationThreshold) {
                $state = $state->terminateInspector($name);
            }
        }

        return $state->incrementChunk();
    }

    /**
     * Check if inspection should terminate early.
     */
    private function shouldTerminate(InspectionState $state): bool
    {
        // Terminate if any inspector has high confidence finding
        foreach ($state->scores as $score) {
            if ($score >= $this->earlyTerminationThreshold) {
                return true;
            }
        }

        // Terminate if combined score is very high
        $avgScore = array_sum($state->scores) / max(count($state->scores), 1);
        if ($avgScore >= 0.9) {
            return true;
        }

        return false;
    }

    /**
     * Create inspection result.
     */
    private function createResult(
        InspectionState $state,
        int $processedChunks,
        int $totalChunks,
        int $totalBytes,
        ?string $checkpointId = null
    ): IncrementalResult {
        $maxScore = max($state->scores ?: [0]);
        $avgScore = array_sum($state->scores) / max(count($state->scores), 1);

        $findings = [];
        foreach ($state->allFindings as $inspector => $inspectorFindings) {
            foreach ($inspectorFindings as $finding) {
                $findings[] = array_merge($finding, ['inspector' => $inspector]);
            }
        }

        return new IncrementalResult(
            $maxScore >= 0.5,
            $maxScore,
            $avgScore,
            $findings,
            $state->scores,
            $processedChunks,
            $totalChunks,
            $totalBytes,
            $processedChunks < $totalChunks,
            $checkpointId
        );
    }

    /**
     * Create SQL injection inspector.
     */
    private function createSqlInspector(): callable
    {
        return function (string $chunk, array $state, int $index): array {
            $patterns = [
                '/\bUNION\s+SELECT\b/i' => 0.9,
                '/\bSELECT\s+.*\s+FROM\b/i' => 0.7,
                '/\bINSERT\s+INTO\b/i' => 0.6,
                '/\bUPDATE\s+.*\s+SET\b/i' => 0.6,
                '/\bDELETE\s+FROM\b/i' => 0.7,
                '/\bDROP\s+(TABLE|DATABASE)\b/i' => 0.95,
                '/\'\s*(OR|AND)\s+[\'"]?[\d]+=[\d]+/i' => 0.8,
                '/--\s*$/m' => 0.4,
                '/;\s*--/' => 0.5,
            ];

            $score = $state['score'] ?? 0;
            $findings = [];

            foreach ($patterns as $pattern => $weight) {
                if (preg_match($pattern, $chunk, $matches)) {
                    $score = max($score, $weight);
                    $findings[] = [
                        'type' => 'sql_pattern',
                        'pattern' => $pattern,
                        'match' => $matches[0],
                        'chunk_index' => $index,
                        'weight' => $weight,
                    ];
                }
            }

            // Check for suspicious character sequences
            $suspiciousChars = substr_count($chunk, "'") + substr_count($chunk, '"');
            if ($suspiciousChars > 10) {
                $score = max($score, 0.3);
            }

            return [
                'state' => ['score' => $score],
                'score' => $score,
                'findings' => $findings,
            ];
        };
    }

    /**
     * Create XSS inspector.
     */
    private function createXssInspector(): callable
    {
        return function (string $chunk, array $state, int $index): array {
            $patterns = [
                '/<script[^>]*>/i' => 0.9,
                '/javascript:/i' => 0.85,
                '/on(load|error|click|mouse|focus|blur)\s*=/i' => 0.8,
                '/<iframe[^>]*>/i' => 0.75,
                '/<embed[^>]*>/i' => 0.7,
                '/<object[^>]*>/i' => 0.7,
                '/expression\s*\(/i' => 0.6,
                '/data:\s*text\/html/i' => 0.8,
                '/vbscript:/i' => 0.8,
            ];

            $score = $state['score'] ?? 0;
            $findings = [];

            foreach ($patterns as $pattern => $weight) {
                if (preg_match($pattern, $chunk, $matches)) {
                    $score = max($score, $weight);
                    $findings[] = [
                        'type' => 'xss_pattern',
                        'pattern' => $pattern,
                        'match' => $matches[0],
                        'chunk_index' => $index,
                        'weight' => $weight,
                    ];
                }
            }

            return [
                'state' => ['score' => $score],
                'score' => $score,
                'findings' => $findings,
            ];
        };
    }

    /**
     * Create path traversal inspector.
     */
    private function createPathTraversalInspector(): callable
    {
        return function (string $chunk, array $state, int $index): array {
            $patterns = [
                '/\.\.[\/\\\\]/' => 0.7,
                '/%2e%2e[%2f%5c]/i' => 0.8,
                '/\.\.%2f/i' => 0.75,
                '/%252e%252e/i' => 0.85,
                '/\.\.[\/\\\\].*(etc|passwd|shadow|boot\.ini)/i' => 0.95,
            ];

            $score = $state['score'] ?? 0;
            $findings = [];
            $traversalCount = ($state['traversal_count'] ?? 0) + substr_count($chunk, '..');

            foreach ($patterns as $pattern => $weight) {
                if (preg_match($pattern, $chunk, $matches)) {
                    $score = max($score, $weight);
                    $findings[] = [
                        'type' => 'path_traversal',
                        'pattern' => $pattern,
                        'match' => $matches[0],
                        'chunk_index' => $index,
                        'weight' => $weight,
                    ];
                }
            }

            // Boost score based on cumulative traversal sequences
            if ($traversalCount > 5) {
                $score = max($score, 0.6);
            }

            return [
                'state' => ['score' => $score, 'traversal_count' => $traversalCount],
                'score' => $score,
                'findings' => $findings,
            ];
        };
    }

    /**
     * Create command injection inspector.
     */
    private function createCommandInjectionInspector(): callable
    {
        return function (string $chunk, array $state, int $index): array {
            $patterns = [
                '/[;&|`]/' => 0.4,
                '/\$\([^)]+\)/' => 0.7,
                '/`[^`]+`/' => 0.7,
                '/\b(cat|ls|pwd|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby)\b/' => 0.6,
                '/>\s*\//' => 0.5,
                '/\|\s*\w+/' => 0.5,
            ];

            $score = $state['score'] ?? 0;
            $findings = [];

            foreach ($patterns as $pattern => $weight) {
                if (preg_match($pattern, $chunk, $matches)) {
                    $score = max($score, $weight);
                    $findings[] = [
                        'type' => 'command_injection',
                        'pattern' => $pattern,
                        'match' => $matches[0],
                        'chunk_index' => $index,
                        'weight' => $weight,
                    ];
                }
            }

            return [
                'state' => ['score' => $score],
                'score' => $score,
                'findings' => $findings,
            ];
        };
    }

    /**
     * Create entropy inspector for detecting encoded/encrypted payloads.
     */
    private function createEntropyInspector(): callable
    {
        return function (string $chunk, array $state, int $index): array {
            $entropy = $this->calculateEntropy($chunk);
            $historicalEntropy = $state['entropy_history'] ?? [];
            $historicalEntropy[] = $entropy;

            // Keep last 10 entropy values
            if (count($historicalEntropy) > 10) {
                $historicalEntropy = array_slice($historicalEntropy, -10);
            }

            $avgEntropy = array_sum($historicalEntropy) / count($historicalEntropy);
            $findings = [];
            $score = 0;

            // High entropy might indicate encoded/encrypted malicious payload
            if ($entropy > 5.0) {
                $score = min(($entropy - 5.0) / 3.0, 0.7);
                $findings[] = [
                    'type' => 'high_entropy',
                    'entropy' => round($entropy, 4),
                    'chunk_index' => $index,
                    'weight' => $score,
                ];
            }

            // Sudden entropy change is suspicious
            if (count($historicalEntropy) > 2) {
                $prevEntropy = $historicalEntropy[count($historicalEntropy) - 2];
                $entropyChange = abs($entropy - $prevEntropy);
                if ($entropyChange > 2.0) {
                    $score = max($score, 0.5);
                    $findings[] = [
                        'type' => 'entropy_spike',
                        'change' => round($entropyChange, 4),
                        'chunk_index' => $index,
                    ];
                }
            }

            return [
                'state' => ['entropy_history' => $historicalEntropy, 'score' => $score],
                'score' => $score,
                'findings' => $findings,
            ];
        };
    }

    /**
     * Calculate Shannon entropy.
     */
    private function calculateEntropy(string $data): float
    {
        if (empty($data)) {
            return 0.0;
        }

        $frequencies = array_count_values(str_split($data));
        $length = strlen($data);
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $p = $count / $length;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }
}

/**
 * Inspection state.
 */
class InspectionState
{
    public array $scores = [];
    public array $inspectorStates = [];
    public array $allFindings = [];
    public array $terminated = [];
    public int $chunksProcessed = 0;

    public function __construct(public readonly array $inspectors)
    {
        foreach (array_keys($inspectors) as $name) {
            $this->scores[$name] = 0;
            $this->inspectorStates[$name] = [];
            $this->allFindings[$name] = [];
            $this->terminated[$name] = false;
        }
    }

    public function getInspectorState(string $name): array
    {
        return $this->inspectorStates[$name] ?? [];
    }

    public function isInspectorTerminated(string $name): bool
    {
        return $this->terminated[$name] ?? false;
    }

    public function updateInspector(
        string $name,
        array $state,
        float $score,
        array $findings
    ): self {
        $new = clone $this;
        $new->inspectorStates[$name] = $state;
        $new->scores[$name] = $score;
        $new->allFindings[$name] = array_merge($new->allFindings[$name], $findings);
        return $new;
    }

    public function terminateInspector(string $name): self
    {
        $new = clone $this;
        $new->terminated[$name] = true;
        return $new;
    }

    public function incrementChunk(): self
    {
        $new = clone $this;
        $new->chunksProcessed++;
        return $new;
    }
}

/**
 * Inspection checkpoint.
 */
class InspectionCheckpoint
{
    public function __construct(
        public readonly string $id,
        public readonly string $content,
        public readonly int $processedChunks,
        public readonly InspectionState $state
    ) {}

    public function withProgress(int $processedChunks, InspectionState $state): self
    {
        return new self($this->id, $this->content, $processedChunks, $state);
    }
}

/**
 * Incremental inspection result.
 */
class IncrementalResult
{
    public function __construct(
        public readonly bool $hasThreat,
        public readonly float $maxScore,
        public readonly float $avgScore,
        public readonly array $findings,
        public readonly array $inspectorScores,
        public readonly int $processedChunks,
        public readonly int $totalChunks,
        public readonly int $totalBytes,
        public readonly bool $incomplete,
        public readonly ?string $checkpointId
    ) {}

    public function toArray(): array
    {
        return [
            'has_threat' => $this->hasThreat,
            'max_score' => round($this->maxScore, 4),
            'avg_score' => round($this->avgScore, 4),
            'findings' => $this->findings,
            'inspector_scores' => array_map(fn($s) => round($s, 4), $this->inspectorScores),
            'processed_chunks' => $this->processedChunks,
            'total_chunks' => $this->totalChunks,
            'total_bytes' => $this->totalBytes,
            'incomplete' => $this->incomplete,
            'checkpoint_id' => $this->checkpointId,
        ];
    }
}
