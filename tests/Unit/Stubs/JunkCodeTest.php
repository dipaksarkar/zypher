<?php

namespace Zypher\Tests\Unit\Stubs;

use Zypher\Tests\AbstractStubTest;

/**
 * Tests encoding with junk code insertion enabled
 */
class JunkCodeTest extends AbstractStubTest
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
        ];
    }

    /**
     * Test encoding basic.php with junk code insertion
     */
    public function testBasicStubWithJunkCode(): void
    {
        $this->assertStubEncodingWorks('basic.php', $this->getOptions());
    }

    /**
     * Test encoding complex.php with junk code insertion
     */
    public function testComplexStubWithJunkCode(): void
    {
        $this->assertStubEncodingWorks('complex.php', $this->getOptions());
    }

    /**
     * Test encoding namespaces.php with junk code insertion
     */
    public function testNamespacesStubWithJunkCode(): void
    {
        $this->assertStubEncodingWorks('namespaces.php', $this->getOptions());
    }

    /**
     * Test encoding all_features.php with junk code insertion
     */
    public function testAllFeaturesStubWithJunkCode(): void
    {
        $this->assertStubEncodingWorks('all_features.php', $this->getOptions());
    }
}
