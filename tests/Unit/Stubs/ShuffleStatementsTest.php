<?php

namespace Zypher\Tests\Unit\Stubs;

use Zypher\Tests\AbstractStubTest;

/**
 * Tests encoding with statement shuffling enabled
 */
class ShuffleStatementsTest extends AbstractStubTest
{
    /**
     * Common options for all tests in this class
     *
     * @return array
     */
    private function getOptions(): array
    {
        return [
            'obfuscate' => true,
            'shuffle_statements' => true
        ];
    }

    /**
     * Test encoding complex.php with statement shuffling
     */
    public function testComplexStubWithShuffleStatements(): void
    {
        $this->assertStubEncodingWorks('complex.php', $this->getOptions());
    }

    /**
     * Test encoding all_features.php with statement shuffling
     */
    public function testAllFeaturesStubWithShuffleStatements(): void
    {
        $this->assertStubEncodingWorks('all_features.php', $this->getOptions());
    }
}
