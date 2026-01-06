<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Performance;

/**
 * Bloom Filter for fast pattern pre-screening.
 *
 * Provides O(1) probabilistic membership testing with no false negatives.
 */
class BloomFilter
{
    protected string $bitmap;
    protected int $size;
    protected int $hashCount;
    protected int $itemCount = 0;

    /**
     * Create a new Bloom filter.
     *
     * @param int $expectedItems Expected number of items
     * @param float $falsePositiveRate Desired false positive rate (0-1)
     */
    public function __construct(int $expectedItems = 10000, float $falsePositiveRate = 0.01)
    {
        // Calculate optimal size: m = -n*ln(p) / (ln(2)^2)
        $this->size = (int) ceil(
            -$expectedItems * log($falsePositiveRate) / (log(2) ** 2)
        );

        // Round up to nearest byte
        $this->size = (int) ceil($this->size / 8) * 8;

        // Calculate optimal hash count: k = (m/n) * ln(2)
        $this->hashCount = (int) ceil(($this->size / $expectedItems) * log(2));
        $this->hashCount = max(1, min($this->hashCount, 20)); // Clamp to 1-20

        // Initialize bitmap
        $this->bitmap = str_repeat("\0", $this->size / 8);
    }

    /**
     * Add an item to the filter.
     */
    public function add(string $item): self
    {
        foreach ($this->getHashes($item) as $hash) {
            $this->setBit($hash);
        }

        $this->itemCount++;

        return $this;
    }

    /**
     * Add multiple items to the filter.
     */
    public function addMany(array $items): self
    {
        foreach ($items as $item) {
            $this->add($item);
        }

        return $this;
    }

    /**
     * Check if item might be in the filter.
     *
     * @return bool True if maybe present, false if definitely not present
     */
    public function mightContain(string $item): bool
    {
        foreach ($this->getHashes($item) as $hash) {
            if (!$this->getBit($hash)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if any substring of input might match filter items.
     */
    public function mightContainSubstring(string $input, int $minLength = 3): bool
    {
        $len = strlen($input);

        for ($i = 0; $i <= $len - $minLength; $i++) {
            // Check progressively longer substrings
            for ($j = $minLength; $j <= min(50, $len - $i); $j++) {
                $substr = substr($input, $i, $j);
                if ($this->mightContain($substr)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get the approximate fill ratio.
     */
    public function getFillRatio(): float
    {
        $setBits = 0;
        $bytes = strlen($this->bitmap);

        for ($i = 0; $i < $bytes; $i++) {
            $byte = ord($this->bitmap[$i]);
            // Count set bits (Brian Kernighan's algorithm)
            while ($byte) {
                $setBits++;
                $byte &= ($byte - 1);
            }
        }

        return $setBits / $this->size;
    }

    /**
     * Get the estimated false positive probability.
     */
    public function getEstimatedFalsePositiveRate(): float
    {
        // p = (1 - e^(-kn/m))^k
        $exponent = -$this->hashCount * $this->itemCount / $this->size;

        return pow(1 - exp($exponent), $this->hashCount);
    }

    /**
     * Get item count.
     */
    public function getItemCount(): int
    {
        return $this->itemCount;
    }

    /**
     * Get filter size in bits.
     */
    public function getSize(): int
    {
        return $this->size;
    }

    /**
     * Export filter state for persistence.
     */
    public function export(): array
    {
        return [
            'bitmap' => base64_encode($this->bitmap),
            'size' => $this->size,
            'hashCount' => $this->hashCount,
            'itemCount' => $this->itemCount,
        ];
    }

    /**
     * Import filter state.
     */
    public static function import(array $data): self
    {
        $filter = new self(1); // Create minimal instance
        $filter->bitmap = base64_decode($data['bitmap']);
        $filter->size = $data['size'];
        $filter->hashCount = $data['hashCount'];
        $filter->itemCount = $data['itemCount'];

        return $filter;
    }

    /**
     * Generate hash values for an item.
     */
    protected function getHashes(string $item): array
    {
        // Use double hashing technique for multiple hashes
        $hash1 = crc32($item) & 0xFFFFFFFF;
        $hash2 = crc32(md5($item)) & 0xFFFFFFFF;

        $hashes = [];
        for ($i = 0; $i < $this->hashCount; $i++) {
            // Linear combination of two base hashes
            $combinedHash = ($hash1 + $i * $hash2) % $this->size;
            $hashes[] = abs($combinedHash);
        }

        return $hashes;
    }

    /**
     * Set a bit in the bitmap.
     */
    protected function setBit(int $position): void
    {
        $byteIndex = (int) floor($position / 8);
        $bitIndex = $position % 8;
        $this->bitmap[$byteIndex] = chr(ord($this->bitmap[$byteIndex]) | (1 << $bitIndex));
    }

    /**
     * Get a bit from the bitmap.
     */
    protected function getBit(int $position): bool
    {
        $byteIndex = (int) floor($position / 8);
        $bitIndex = $position % 8;

        return (ord($this->bitmap[$byteIndex]) & (1 << $bitIndex)) !== 0;
    }

    /**
     * Clear the filter.
     */
    public function clear(): void
    {
        $this->bitmap = str_repeat("\0", strlen($this->bitmap));
        $this->itemCount = 0;
    }
}
