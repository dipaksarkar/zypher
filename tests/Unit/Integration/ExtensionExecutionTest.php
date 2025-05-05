<?php

namespace Zypher\Tests\Unit\Integration;

use PHPUnit\Framework\TestCase;

/**
 * Integration tests that verify encoded files can be executed
 * when the Zypher extension is installed
 */
class ExtensionExecutionTest extends TestCase
{
    /**
     * Directory containing stub files
     */
    protected const STUB_DIR = __DIR__ . '/../../../tests/stubs';

    /**
     * Directory for output encoded files
     */
    protected const OUTPUT_DIR = __DIR__ . '/../../../tests/output';

    /**
     * Path to the encoder script
     */
    protected const ENCODER_SCRIPT = __DIR__ . '/../../../bin/zypher-encode';

    /**
     * Skip test if the Zypher extension is not installed
     */
    protected function setUp(): void
    {
        parent::setUp();

        if (!extension_loaded('zypher')) {
            $this->markTestSkipped('Zypher extension is not loaded. Skipping integration tests.');
        }

        // Ensure output directory exists
        if (!is_dir(self::OUTPUT_DIR)) {
            mkdir(self::OUTPUT_DIR, 0777, true);
        }
    }

    /**
     * Test executing a basic encoded file with the extension
     */
    public function testBasicEncodedExecution(): void
    {
        $testFile = self::STUB_DIR . '/basic.php';
        $encodedFile = self::OUTPUT_DIR . '/test_basic_encoded.php';

        // Encode the file
        $this->encodeFile($testFile, $encodedFile);

        // Execute the original file and get the result
        $originalResult = $this->executePhpFile($testFile);

        // Execute the encoded file and get the result
        $encodedResult = $this->executePhpFile($encodedFile);

        // Compare the results
        $this->assertEquals(
            $originalResult['return'],
            $encodedResult['return'],
            'Encoded file execution did not return the same value as the original file'
        );
    }

    /**
     * Test executing an encoded file with obfuscation options
     */
    public function testObfuscatedEncodedExecution(): void
    {
        $testFile = self::STUB_DIR . '/complex.php';
        $encodedFile = self::OUTPUT_DIR . '/test_obfuscation_encoded.php';

        // Encode the file with obfuscation options
        $this->encodeFile($testFile, $encodedFile, ['--obfuscate', '--string-encryption', '--junk-code']);

        // Execute the original file and get the result
        $originalResult = $this->executePhpFile($testFile);

        // Execute the encoded file and get the result
        $encodedResult = $this->executePhpFile($encodedFile);

        // Compare the results
        $this->assertEquals(
            $originalResult['return'],
            $encodedResult['return'],
            'Obfuscated encoded file execution did not return the same value as the original file'
        );
    }

    /**
     * Test executing an encoded file with a custom master key
     */
    public function testCustomMasterKeyEncoding(): void
    {
        $testFile = self::STUB_DIR . '/basic.php';
        $encodedFile = self::OUTPUT_DIR . '/test_master_key_encoded.php';
        $masterKey = 'CustomTestKey2023!@#';

        // Encode the file with a custom master key
        $this->encodeFile($testFile, $encodedFile, ['--master-key=' . $masterKey]);

        // Set an environment variable for the Zypher extension to use the custom master key
        // This assumes the extension has been compiled with support for environment variables
        putenv('ZYPHER_MASTER_KEY=' . $masterKey);

        try {
            // Execute the original file and get the result
            $originalResult = $this->executePhpFile($testFile);

            // Execute the encoded file and get the result
            $encodedResult = $this->executePhpFile($encodedFile);

            // Compare the results
            $this->assertEquals(
                $originalResult['return'],
                $encodedResult['return'],
                'Custom master key encoded file execution did not return the same value as the original file'
            );
        } finally {
            // Remove the environment variable
            putenv('ZYPHER_MASTER_KEY=');
        }
    }

    /**
     * Test executing a large file to verify performance
     */
    public function testLargeFileEncoding(): void
    {
        $testFile = self::STUB_DIR . '/all_features.php';
        $encodedFile = self::OUTPUT_DIR . '/test_large_php_encoded.php';

        // Encode the file
        $this->encodeFile($testFile, $encodedFile);

        // Execute the original file and get the result
        $originalResult = $this->executePhpFile($testFile);

        // Execute the encoded file and get the result
        $encodedResult = $this->executePhpFile($encodedFile);

        // Compare the results
        $this->assertEquals(
            $originalResult['return'],
            $encodedResult['return'],
            'Large encoded file execution did not return the same value as the original file'
        );
    }

    /**
     * Test executing files with all combined obfuscation options
     */
    public function testAllOptionsEncodedExecution(): void
    {
        $testFile = self::STUB_DIR . '/all_features.php';
        $encodedFile = self::OUTPUT_DIR . '/test_multiple_options_encoded.php';

        // Encode the file with all available options
        $this->encodeFile(
            $testFile,
            $encodedFile,
            [
                '--obfuscate',
                '--string-encryption',
                '--junk-code',
                '--shuffle-stmts',
                '--master-key=TestAllOptions'
            ]
        );

        // Set environment variable for the custom master key
        putenv('ZYPHER_MASTER_KEY=TestAllOptions');

        try {
            // Execute the original file and get the result
            $originalResult = $this->executePhpFile($testFile);

            // Execute the encoded file and get the result
            $encodedResult = $this->executePhpFile($encodedFile);

            // Compare the results
            $this->assertEquals(
                $originalResult['return'],
                $encodedResult['return'],
                'Multiple options encoded file execution did not return the same value as the original file'
            );
        } finally {
            // Remove the environment variable
            putenv('ZYPHER_MASTER_KEY=');
        }
    }

    /**
     * Run a PHP file and capture its output and return value
     *
     * @param string $filePath Path to the PHP file to execute
     * @return array Array with 'output' and 'return' keys
     */
    protected function executePhpFile(string $filePath): array
    {
        // Start output buffering to capture output
        ob_start();

        // Execute the file and get the return value
        $returnValue = include $filePath;

        // Get the captured output
        $output = ob_get_clean();

        return [
            'output' => $output,
            'return' => $returnValue
        ];
    }

    /**
     * Encode a source file using the Zypher encoder
     *
     * @param string $sourcePath Path to the source file
     * @param string $outputPath Path for the encoded output file
     * @param array $options Additional command-line options
     * @return string Command output
     */
    protected function encodeFile(string $sourcePath, string $outputPath, array $options = []): string
    {
        $cmd = escapeshellcmd(self::ENCODER_SCRIPT) . ' ' .
            escapeshellarg($sourcePath) . ' ' .
            escapeshellarg($outputPath) . ' --quiet';

        // Add any additional options
        foreach ($options as $option) {
            $cmd .= ' ' . escapeshellarg($option);
        }

        // Execute the command
        $output = shell_exec($cmd . ' 2>&1');

        // Verify the encoded file exists
        $this->assertFileExists($outputPath, "Encoded file was not created");

        return $output ?: '';
    }
}
