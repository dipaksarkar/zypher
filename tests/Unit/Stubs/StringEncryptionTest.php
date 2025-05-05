<?php

namespace Zypher\Tests\Unit\Stubs;

use Zypher\Tests\AbstractStubTest;

/**
 * Tests encoding with string encryption enabled
 */
class StringEncryptionTest extends AbstractStubTest
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
            'string_encryption' => true
        ];
    }

    /**
     * Test encoding basic.php with string encryption
     */
    public function testBasicStubWithStringEncryption(): void
    {
        $this->assertStubEncodingWorks('basic.php', $this->getOptions());
    }

    /**
     * Test encoding strings.php with string encryption
     */
    public function testStringsStubWithStringEncryption(): void
    {
        $this->assertStubEncodingWorks('strings.php', $this->getOptions());
    }

    /**
     * Test encoding complex.php with string encryption
     */
    public function testComplexStubWithStringEncryption(): void
    {
        $this->assertStubEncodingWorks('complex.php', $this->getOptions());
    }

    /**
     * Test encoding namespaces.php with string encryption
     */
    public function testNamespacesStubWithStringEncryption(): void
    {
        $this->assertStubEncodingWorks('namespaces.php', $this->getOptions());
    }

    /**
     * Test encoding all_features.php with string encryption
     */
    public function testAllFeaturesStubWithStringEncryption(): void
    {
        $this->assertStubEncodingWorks('all_features.php', $this->getOptions());
    }
}
