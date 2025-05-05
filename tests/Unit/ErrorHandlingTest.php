<?php

namespace Zypher\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Zypher\ZypherEncoder;
use Zypher\EncoderOptions;

/**
 * Tests error handling in the Zypher encoder
 */
class ErrorHandlingTest extends TestCase
{
    /**
     * Directory for temporary test files
     */
    protected const TEMP_DIR = __DIR__ . '/../../tests/temp';

    /**
     * Setup test environment
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Ensure temp directory exists
        if (!is_dir(self::TEMP_DIR)) {
            mkdir(self::TEMP_DIR, 0777, true);
        }
    }

    /**
     * Clean up after test
     */
    protected function tearDown(): void
    {
        parent::tearDown();

        // Clean up temporary files
        $this->removeDirectory(self::TEMP_DIR);
    }

    /**
     * Test handling of non-existent source file
     */
    public function testNonExistentSourceFile(): void
    {
        $options = new EncoderOptions();
        $encoder = new ZypherEncoder($options);

        $nonExistentFile = self::TEMP_DIR . '/does_not_exist.php';
        $outputFile = self::TEMP_DIR . '/output.php';

        // Capture output to avoid polluting test results
        ob_start();
        $stats = $encoder->processPath($nonExistentFile, $outputFile);
        ob_end_clean();

        // Expect errors count to be incremented
        $this->assertGreaterThan(0, $stats['errors'], 'Encoder should report errors for non-existent files');

        // Output file should not be created
        $this->assertFileDoesNotExist($outputFile, 'Output file should not be created for non-existent source');
    }

    /**
     * Test handling of invalid PHP syntax in source file
     */
    public function testInvalidPhpSyntax(): void
    {
        $invalidCode = '<?php echo "Unclosed string; ?>';
        $invalidFile = self::TEMP_DIR . '/invalid.php';
        $outputFile = self::TEMP_DIR . '/invalid_output.php';

        // Create a file with invalid PHP syntax
        file_put_contents($invalidFile, $invalidCode);

        // Initialize encoder
        $options = new EncoderOptions();
        $encoder = new ZypherEncoder($options);

        // Encode the invalid file
        ob_start();
        $encoder->processPath($invalidFile, $outputFile);
        $output = ob_get_clean();

        // Check if encoder processed the file without a fatal error
        $this->assertFileExists($outputFile, 'Encoder should still create an output file for PHP with syntax errors');

        // The encoded file might still be generated, but if executed, the PHP parser will catch the syntax error
    }

    /**
     * Test handling of invalid output directory
     */
    public function testInvalidOutputDirectory(): void
    {
        // Create a read-only directory if possible
        $readOnlyDir = self::TEMP_DIR . '/readonly';
        mkdir($readOnlyDir, 0777, true);

        // Create a sample file
        $sourceFile = self::TEMP_DIR . '/test.php';
        file_put_contents($sourceFile, '<?php echo "Test"; ?>');

        // Try to make the directory read-only
        // Note: This may not work on all systems depending on permissions
        try {
            chmod($readOnlyDir, 0555); // read+execute, but no write

            $outputFile = $readOnlyDir . '/subdir/output.php';

            $options = new EncoderOptions();
            $encoder = new ZypherEncoder($options);

            // Capture output
            ob_start();
            $stats = $encoder->processPath($sourceFile, $outputFile);
            ob_end_clean();

            // Expect errors
            $this->assertGreaterThan(0, $stats['errors'], 'Encoder should report errors for invalid output directory');
        } finally {
            // Restore permissions to allow cleanup
            chmod($readOnlyDir, 0777);
        }
    }

    /**
     * Test handling of very large files
     */
    public function testLargeFilesHandling(): void
    {
        // Skip if on a system with low memory
        if (ini_get('memory_limit') && (int)ini_get('memory_limit') < 256) {
            $this->markTestSkipped('Not enough memory available to test large files');
        }

        // Create a large PHP file (2MB)
        $largeFile = self::TEMP_DIR . '/large.php';
        $outputFile = self::TEMP_DIR . '/large_output.php';

        // Generate large file with valid PHP
        $this->generateLargePhpFile($largeFile, 2 * 1024 * 1024); // 2MB

        // Initialize encoder with quiet mode to avoid too much output
        $options = new EncoderOptions();
        $options->quietMode = true;
        $encoder = new ZypherEncoder($options);

        // Encode the file
        $stats = $encoder->processPath($largeFile, $outputFile);

        // Check if encoding was successful
        $this->assertGreaterThan(0, $stats['processed'], 'Encoder should process large files');
        $this->assertEquals(0, $stats['errors'], 'Encoder should handle large files without errors');

        // Verify output file exists and is not empty
        $this->assertFileExists($outputFile, 'Output file should be created for large files');
        $this->assertGreaterThan(0, filesize($outputFile), 'Output file should not be empty');
    }

    /**
     * Test handling of empty files
     */
    public function testEmptyFileHandling(): void
    {
        // Create an empty PHP file
        $emptyFile = self::TEMP_DIR . '/empty.php';
        $outputFile = self::TEMP_DIR . '/empty_output.php';

        file_put_contents($emptyFile, '<?php ?>');

        // Initialize encoder
        $options = new EncoderOptions();
        $encoder = new ZypherEncoder($options);

        // Encode the empty file
        ob_start();
        $stats = $encoder->processPath($emptyFile, $outputFile);
        ob_end_clean();

        // Empty files should still be processed
        $this->assertEquals(1, $stats['processed'], 'Encoder should process empty files');
        $this->assertEquals(0, $stats['errors'], 'Encoder should not report errors for empty files');

        // Check that the output file exists
        $this->assertFileExists($outputFile, 'Output file should be created for empty files');
    }

    /**
     * Helper method to recursively remove a directory
     *
     * @param string $dir Directory to remove
     */
    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);

        foreach ($files as $file) {
            $path = $dir . '/' . $file;

            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                unlink($path);
            }
        }

        rmdir($dir);
    }

    /**
     * Generate a large PHP file with valid syntax
     *
     * @param string $filePath Path to create the file
     * @param int $size Approximate size in bytes
     */
    private function generateLargePhpFile(string $filePath, int $size): void
    {
        $handle = fopen($filePath, 'w');

        fwrite($handle, "<?php\n");
        fwrite($handle, "/**\n");
        fwrite($handle, " * Large test file for Zypher Encoder\n");
        fwrite($handle, " * Generated for testing purposes\n");
        fwrite($handle, " */\n\n");

        fwrite($handle, "// Large array of data\n");
        fwrite($handle, "\$largeArray = [\n");

        $currentSize = ftell($handle);
        $lineSize = 100; // Average line size estimate
        $lines = ($size - $currentSize - 100) / $lineSize; // Subtract some buffer for closing

        for ($i = 0; $i < $lines; $i++) {
            $line = "    'key_$i' => '" . str_repeat('x', 50) . rand(1000, 9999) . "',\n";
            fwrite($handle, $line);
        }

        fwrite($handle, "];\n\n");
        fwrite($handle, "// Process large array\n");
        fwrite($handle, "function processArray(\$array) {\n");
        fwrite($handle, "    \$result = [];\n");
        fwrite($handle, "    foreach (\$array as \$key => \$value) {\n");
        fwrite($handle, "        \$result[\$key] = substr(\$value, 0, 10);\n");
        fwrite($handle, "    }\n");
        fwrite($handle, "    return \$result;\n");
        fwrite($handle, "}\n\n");
        fwrite($handle, "// Return result\n");
        fwrite($handle, "return ['status' => 'success', 'count' => count(\$largeArray)];\n");

        fclose($handle);
    }
}
