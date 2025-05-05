<?php

namespace Zypher\Tests\Unit\Stubs;

use Zypher\Tests\AbstractStubTest;

/**
 * Tests encoding with obfuscation enabled
 */
class ObfuscationTest extends AbstractStubTest
{
    /**
     * Common options for all tests in this class
     *
     * @return array
     */
    private function getOptions(): array
    {
        return [
            'obfuscate' => true
        ];
    }

    /**
     * Test encoding basic.php with obfuscation
     */
    public function testBasicStubObfuscation(): void
    {
        $this->assertStubEncodingWorks('basic.php', $this->getOptions());
    }

    /**
     * Test encoding oop.php with obfuscation
     */
    public function testOopStubObfuscation(): void
    {
        $this->assertStubEncodingWorks('oop.php', $this->getOptions());
    }

    /**
     * Test encoding strings.php with obfuscation
     */
    public function testStringsStubObfuscation(): void
    {
        $this->assertStubEncodingWorks('strings.php', $this->getOptions());
    }

    /**
     * Test encoding complex.php with obfuscation
     */
    public function testComplexStubObfuscation(): void
    {
        $this->assertStubEncodingWorks('complex.php', $this->getOptions());
    }

    /**
     * Test encoding namespaces.php with obfuscation
     */
    public function testNamespacesStubObfuscation(): void
    {
        $this->assertStubEncodingWorks('namespaces.php', $this->getOptions());
    }

    /**
     * Test encoding application.php with obfuscation
     */
    public function testApplicationStubObfuscation(): void
    {
        $this->assertStubEncodingWorks('application.php', $this->getOptions());
    }

    /**
     * Test encoding all_features.php with obfuscation
     */
    public function testAllFeaturesStubObfuscation(): void
    {
        $this->assertStubEncodingWorks('all_features.php', $this->getOptions());
    }

    /**
     * Test encoding serialization.php with obfuscation
     */
    public function testSerializationStubObfuscation(): void
    {
        $this->assertStubEncodingWorks('serialization.php', $this->getOptions());
    }
}
