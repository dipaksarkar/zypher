<?php

namespace Zypher\Tests\Unit\Stubs;

use Zypher\Tests\AbstractStubTest;

/**
 * Tests encoding with a custom master key
 */
class CustomMasterKeyTest extends AbstractStubTest
{
    /**
     * Common options for all tests in this class
     *
     * @return array
     */
    private function getOptions(): array
    {
        return [
            'masterKey' => 'CustomTestMasterKey2023!@#'
        ];
    }

    /**
     * Test encoding basic.php with custom master key
     */
    public function testBasicStubWithCustomMasterKey(): void
    {
        $this->assertStubEncodingWorks('basic.php', $this->getOptions());
    }

    /**
     * Test encoding all_features.php with custom master key
     */
    public function testAllFeaturesStubWithCustomMasterKey(): void
    {
        $this->assertStubEncodingWorks('all_features.php', $this->getOptions());
    }
}
