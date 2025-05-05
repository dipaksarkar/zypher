<?php

namespace Zypher\Tests\Unit\Stubs;

use Zypher\Tests\AbstractStubTest;

/**
 * Tests encoding with all obfuscation options enabled together
 */
class CombinedOptionsTest extends AbstractStubTest
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
            'string_encryption' => true,
            'junk_code' => true,
            'shuffle_statements' => true,
            'masterKey' => 'ComplexCombinedTestKey$2023'
        ];
    }

    /**
     * Test encoding complex.php with all obfuscation options
     */
    public function testComplexStubWithAllOptions(): void
    {
        $this->assertStubEncodingWorks('complex.php', $this->getOptions());
    }

    /**
     * Test encoding all_features.php with all obfuscation options
     */
    public function testAllFeaturesStubWithAllOptions(): void
    {
        $this->assertStubEncodingWorks('all_features.php', $this->getOptions());
    }
}
