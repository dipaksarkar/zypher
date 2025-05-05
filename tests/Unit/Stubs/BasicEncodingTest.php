<?php

namespace Zypher\Tests\Unit\Stubs;

use Zypher\Tests\AbstractStubTest;

/**
 * Tests basic encoding with default options
 */
class BasicEncodingTest extends AbstractStubTest
{
    /**
     * Test encoding basic.php with default options
     */
    public function testBasicStub(): void
    {
        $this->assertStubEncodingWorks('basic.php');
    }

    /**
     * Test encoding oop.php with default options
     */
    public function testOopStub(): void
    {
        $this->assertStubEncodingWorks('oop.php');
    }

    /**
     * Test encoding strings.php with default options
     */
    public function testStringsStub(): void
    {
        $this->assertStubEncodingWorks('strings.php');
    }

    /**
     * Test encoding complex.php with default options
     */
    public function testComplexStub(): void
    {
        $this->assertStubEncodingWorks('complex.php');
    }

    /**
     * Test encoding namespaces.php with default options
     */
    public function testNamespacesStub(): void
    {
        $this->assertStubEncodingWorks('namespaces.php');
    }

    /**
     * Test encoding application.php with default options
     */
    public function testApplicationStub(): void
    {
        $this->assertStubEncodingWorks('application.php');
    }

    /**
     * Test encoding all_features.php with default options
     */
    public function testAllFeaturesStub(): void
    {
        $this->assertStubEncodingWorks('all_features.php');
    }

    /**
     * Test encoding serialization.php with default options
     */
    public function testSerializationStub(): void
    {
        $this->assertStubEncodingWorks('serialization.php');
    }
}
