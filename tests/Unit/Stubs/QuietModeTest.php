<?php

namespace Zypher\Tests\Unit\Stubs;

use Zypher\Tests\AbstractStubTest;

/**
 * Tests encoding with quiet mode enabled
 */
class QuietModeTest extends AbstractStubTest
{
    /**
     * Common options for all tests in this class
     *
     * @return array
     */
    private function getOptions(): array
    {
        return [
            'quietMode' => true
        ];
    }

    /**
     * Test encoding basic.php with quiet mode
     */
    public function testBasicStubWithQuietMode(): void
    {
        $this->assertStubEncodingWorks('basic.php', $this->getOptions());
    }

    /**
     * Test encoding all_features.php with quiet mode
     */
    public function testAllFeaturesStubWithQuietMode(): void
    {
        $this->assertStubEncodingWorks('all_features.php', $this->getOptions());
    }
}
