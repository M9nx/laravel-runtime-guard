<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Performance;

use Mounir\RuntimeGuard\Contracts\GuardInterface;
use Mounir\RuntimeGuard\Contracts\GuardResultInterface;
use Generator;

/**
 * Streaming Input Inspector.
 *
 * Processes large inputs in chunks to reduce memory usage.
 */
class StreamingInspector
{
    protected int $chunkSize;
    protected int $maxInputSize;
    protected int $overlapSize;
    protected array $guards = [];

    public function __construct(
        int $chunkSize = 8192,
        int $maxInputSize = 10 * 1024 * 1024, // 10MB
        int $overlapSize = 256
    ) {
        $this->chunkSize = $chunkSize;
        $this->maxInputSize = $maxInputSize;
        $this->overlapSize = $overlapSize;
    }

    /**
     * Set guards to use for inspection.
     */
    public function setGuards(array $guards): self
    {
        $this->guards = $guards;

        return $this;
    }

    /**
     * Inspect a large string input in chunks.
     */
    public function inspectString(string $input, array $context = []): StreamingResult
    {
        $inputSize = strlen($input);
        $result = new StreamingResult();

        // Check size limit
        if ($inputSize > $this->maxInputSize) {
            $result->addWarning('Input exceeds maximum size, truncating');
            $input = substr($input, 0, $this->maxInputSize);
            $inputSize = $this->maxInputSize;
        }

        // For small inputs, process directly
        if ($inputSize <= $this->chunkSize) {
            return $this->inspectChunk($input, 0, $context, $result);
        }

        // Process in chunks with overlap
        $offset = 0;
        $chunkIndex = 0;

        while ($offset < $inputSize) {
            $chunk = substr($input, $offset, $this->chunkSize + $this->overlapSize);
            $result = $this->inspectChunk($chunk, $offset, $context, $result);

            // Stop early if critical threat found
            if ($result->hasCriticalThreat()) {
                break;
            }

            $offset += $this->chunkSize;
            $chunkIndex++;
        }

        $result->setChunksProcessed($chunkIndex + 1);

        return $result;
    }

    /**
     * Inspect a stream/resource.
     */
    public function inspectStream($stream, array $context = []): StreamingResult
    {
        if (!is_resource($stream)) {
            throw new \InvalidArgumentException('Expected a stream resource');
        }

        $result = new StreamingResult();
        $offset = 0;
        $chunkIndex = 0;
        $buffer = '';

        while (!feof($stream)) {
            $data = fread($stream, $this->chunkSize);
            if ($data === false) {
                break;
            }

            // Prepend overlap from previous chunk
            $chunk = $buffer . $data;

            // Save overlap for next chunk
            if (strlen($data) === $this->chunkSize) {
                $buffer = substr($chunk, -$this->overlapSize);
            } else {
                $buffer = '';
            }

            $result = $this->inspectChunk($chunk, $offset, $context, $result);

            if ($result->hasCriticalThreat()) {
                break;
            }

            $offset += strlen($data);
            $chunkIndex++;

            // Check size limit
            if ($offset > $this->maxInputSize) {
                $result->addWarning('Stream exceeds maximum size, stopping');
                break;
            }
        }

        $result->setChunksProcessed($chunkIndex);

        return $result;
    }

    /**
     * Inspect using a generator for memory efficiency.
     */
    public function inspectGenerator(Generator $generator, array $context = []): StreamingResult
    {
        $result = new StreamingResult();
        $offset = 0;
        $chunkIndex = 0;

        foreach ($generator as $chunk) {
            if (!is_string($chunk)) {
                $chunk = (string) $chunk;
            }

            $result = $this->inspectChunk($chunk, $offset, $context, $result);

            if ($result->hasCriticalThreat()) {
                break;
            }

            $offset += strlen($chunk);
            $chunkIndex++;

            if ($offset > $this->maxInputSize) {
                $result->addWarning('Generator output exceeds maximum size');
                break;
            }
        }

        $result->setChunksProcessed($chunkIndex);

        return $result;
    }

    /**
     * Inspect a single chunk.
     */
    protected function inspectChunk(
        string $chunk,
        int $offset,
        array $context,
        StreamingResult $result
    ): StreamingResult {
        $chunkContext = array_merge($context, [
            'chunk_offset' => $offset,
            'chunk_size' => strlen($chunk),
        ]);

        foreach ($this->guards as $guard) {
            if (!$guard instanceof GuardInterface || !$guard->isEnabled()) {
                continue;
            }

            $guardResult = $guard->inspect($chunk, $chunkContext);

            if ($guardResult->failed()) {
                $result->addThreat($guard->getName(), $guardResult, $offset);
            }
        }

        return $result;
    }

    /**
     * Create a chunked generator from a string.
     */
    public function chunkString(string $input): Generator
    {
        $length = strlen($input);

        for ($i = 0; $i < $length; $i += $this->chunkSize) {
            yield substr($input, $i, $this->chunkSize + $this->overlapSize);
        }
    }

    /**
     * Set chunk size.
     */
    public function setChunkSize(int $size): self
    {
        $this->chunkSize = max(1024, $size);

        return $this;
    }

    /**
     * Set maximum input size.
     */
    public function setMaxInputSize(int $size): self
    {
        $this->maxInputSize = $size;

        return $this;
    }

    /**
     * Set overlap size.
     */
    public function setOverlapSize(int $size): self
    {
        $this->overlapSize = $size;

        return $this;
    }
}

/**
 * Result container for streaming inspection.
 */
class StreamingResult
{
    protected array $threats = [];
    protected array $warnings = [];
    protected int $chunksProcessed = 0;
    protected bool $hasCritical = false;

    public function addThreat(string $guard, GuardResultInterface $result, int $offset): void
    {
        $this->threats[] = [
            'guard' => $guard,
            'result' => $result,
            'offset' => $offset,
        ];

        if ($result->getThreatLevel()?->value >= 4) { // CRITICAL
            $this->hasCritical = true;
        }
    }

    public function addWarning(string $message): void
    {
        $this->warnings[] = $message;
    }

    public function setChunksProcessed(int $count): void
    {
        $this->chunksProcessed = $count;
    }

    public function getThreats(): array
    {
        return $this->threats;
    }

    public function getWarnings(): array
    {
        return $this->warnings;
    }

    public function getChunksProcessed(): int
    {
        return $this->chunksProcessed;
    }

    public function hasCriticalThreat(): bool
    {
        return $this->hasCritical;
    }

    public function hasThreats(): bool
    {
        return !empty($this->threats);
    }

    public function getThreatCount(): int
    {
        return count($this->threats);
    }

    public function toArray(): array
    {
        return [
            'threats' => array_map(function ($t) {
                return [
                    'guard' => $t['guard'],
                    'message' => $t['result']->getMessage(),
                    'level' => $t['result']->getThreatLevel()?->name,
                    'offset' => $t['offset'],
                ];
            }, $this->threats),
            'warnings' => $this->warnings,
            'chunks_processed' => $this->chunksProcessed,
            'has_critical' => $this->hasCritical,
        ];
    }
}
