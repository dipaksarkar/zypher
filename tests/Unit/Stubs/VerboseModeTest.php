<?php

namespace Zypher\Tests\Unit\Stubs;

use Zypher\Tests\AbstractStubTest;

/**
 * Tests encoding with verbose mode enabled
 */
class VerboseModeTest extends AbstractStubTest
{
    /**
     * Common options for all tests in this class
     *
     * @return array
     */
    private function getOptions(): array
    {
        return [
            'verboseMode' => true
        ];
    }

    /**
     * Test encoding basic.php with verbose mode
     */
    public function testBasicStubWithVerboseMode(): void
    {
        $this->assertStubEncodingWorks('basic.php', $this->getOptions());
    }

    /**
     * Test encoding all_features.php with verbose mode
     */
    public function testAllFeaturesStubWithVerboseMode(): void
    {
        $this->assertStubEncodingWorks('all_features.php', $this->getOptions());
    }
}
