<?php

namespace Zypher\Tests;

use PHPUnit\Framework\SkippedTest;
use PHPUnit\Framework\TestCase;
use Zypher\ZypherEncoder;
use Zypher\EncoderOptions;

/**
 * Base class for all stub test cases.
 * Contains common methods for encoding files and comparing results.
 */
abstract class AbstractStubTest extends TestCase
{
    /**
     * Directory containing stub files
     */
    protected const STUB_DIR = __DIR__ . '/stubs';

    /**
     * Directory for output encoded files
     */
    protected const OUTPUT_DIR = __DIR__ . '/output';

    /**
     * Setup test environment
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Ensure output directory exists
        if (!is_dir(self::OUTPUT_DIR)) {
            mkdir(self::OUTPUT_DIR, 0777, true);
        }

        // Ensure stub directory exists
        $this->assertTrue(is_dir(self::STUB_DIR), 'Stub directory not found: ' . self::STUB_DIR);
    }

    /**
     * Get a filepath to a stub file
     *
     * @param string $filename The stub filename
     * @return string Full path to the stub file
     */
    protected function getStubPath(string $filename): string
    {
        $path = self::STUB_DIR . '/' . $filename;
        $this->assertFileExists($path, "Stub file not found: $path");
        return $path;
    }

    /**
     * Get a filepath for an encoded output file
     *
     * @param string $filename The original stub filename
     * @return string Full path to the encoded output file
     */
    protected function getOutputPath(string $filename): string
    {
        $basename = pathinfo($filename, PATHINFO_FILENAME);
        return self::OUTPUT_DIR . '/' . $basename . '_encoded.php';
    }

    /**
     * Run a PHP file and capture its output and return value
     *
     * @param string $filePath Path to the PHP file to execute
     * @return array Array with 'output' and 'return' keys
     */
    protected function executePhpFile(string $filePath): array
    {
        $this->assertFileExists($filePath, "File not found: $filePath");

        // Prepare command to execute the PHP file
        // Use -d display_errors=1 to ensure errors are displayed
        $command = 'php -d display_errors=1 ' . escapeshellarg($filePath) . ' 2>&1';

        // Execute the command and capture output
        exec($command, $outputLines, $returnCode);
        $output = implode(PHP_EOL, $outputLines);

        // For testing, also try to extract a return value if the file uses echo/print for JSON
        $returnValue = null;
        if (preg_match('/\{.*\}/s', $output, $matches)) {
            $jsonString = $matches[0];
            $returnValue = @json_decode($jsonString, true);
        }

        return [
            'output' => $output,
            'return' => $returnValue,
            'returnCode' => $returnCode
        ];
    }

    /**
     * Determine if the Zypher loader extension is available
     * 
     * @return bool True if the extension is available
     */
    protected function isLoaderAvailable(): bool
    {
        // Check if the extension is available in the system
        // This runs a simple command to check if the extension is loaded
        $result = shell_exec("php -r 'echo extension_loaded(\"zypher\") ? \"yes\" : \"no\";'");
        return trim($result) === "yes";
    }

    /**
     * Encode a stub file using provided options
     *
     * @param string $stubFile The stub file name
     * @param array $options Additional encoding options
     * @return string Path to the encoded file
     */
    protected function encodeStub(string $stubFile, array $options = []): string
    {
        $stubPath = $this->getStubPath($stubFile);
        $outputPath = $this->getOutputPath($stubFile);

        // Initialize encoder options
        $encoderOptions = new EncoderOptions();

        // Apply test options
        foreach ($options as $key => $value) {
            if (property_exists($encoderOptions, $key)) {
                $encoderOptions->$key = $value;
            } else if ($key === 'obfuscate') {
                $encoderOptions->obfuscation['enabled'] = (bool)$value;
            } else if (isset($encoderOptions->obfuscation[$key])) {
                $encoderOptions->obfuscation[$key] = (bool)$value;
            }
        }

        // Enable quiet mode by default for tests to reduce output noise
        if (!isset($options['quietMode']) && !isset($options['verboseMode'])) {
            $encoderOptions->quietMode = true;
        }

        // Create encoder instance
        $encoder = new ZypherEncoder($encoderOptions);

        // Encode the file
        $result = $encoder->processPath($stubPath, $outputPath);
        $this->assertIsArray($result, "The encoder did not return stats array");
        $this->assertArrayHasKey('processed', $result, "The encoder stats don't have 'processed' key");

        return $outputPath;
    }

    /**
     * Run both the original stub file and its encoded version,
     * then compare their results.
     *
     * @param string $stubFile The stub file name to test
     * @param array $options Encoding options to apply
     */
    protected function assertStubEncodingWorks(string $stubFile, array $options = []): void
    {
        // Encode the stub file and get the encoded file path
        $encodedPath = $this->encodeStub($stubFile, $options);
        $stubPath = $this->getStubPath($stubFile);

        // Make sure the encoded file exists
        $this->assertFileExists($encodedPath, "Encoded file was not created");
        $this->assertTrue(filesize($encodedPath) > 0, "Encoded file is empty");

        // Check that the encoded file has the Zypher signature
        $encodedContent = file_get_contents($encodedPath);
        $this->assertStringContainsString('ZYPH01', $encodedContent, "Encoded file doesn't contain the Zypher signature");

        // Step 1: Execute the original stub file and get its output/return value
        $originalResults = $this->executePhpFile($stubPath);
        echo "\nOriginal file output: $stubPath\n";
        echo "---------------------\n";
        echo json_encode($originalResults); // Debugging output

        // Check if we can perform loader-based testing
        if (!$this->isLoaderAvailable()) {
            $this->markTestSkipped("Zypher loader extension not available. Skipping execution comparison test.");
            return;
        }

        try {
            // Step 2: Execute the encoded file with the loader extension and get its output/return value
            $encodedResults = $this->executePhpFile($encodedPath);

            // Step 3: Compare the results to ensure they match
            echo "\nComparing results: $encodedPath\n";
            echo "---------------------\n";
            echo json_encode($encodedResults); // Debugging output

            // Compare return codes
            $this->assertEquals(
                $originalResults['returnCode'],
                $encodedResults['returnCode'],
                "Return codes differ between original and encoded file execution"
            );

            // Normalize outputs (remove timestamps, system-specific paths, etc)
            $originalOutput = $this->normalizeOutput($originalResults['output']);
            $encodedOutput = $this->normalizeOutput($encodedResults['output']);

            // Debug mode: write outputs to files for inspection if they differ
            if ($originalOutput !== $encodedOutput) {
                file_put_contents(self::OUTPUT_DIR . '/debug_original_output.txt', $originalOutput);
                file_put_contents(self::OUTPUT_DIR . '/debug_encoded_output.txt', $encodedOutput);
            }

            // Compare outputs
            $this->assertEquals(
                $originalOutput,
                $encodedOutput,
                "Output differs between original and encoded file execution"
            );

            // If JSON return values were extracted, compare them too
            if ($originalResults['return'] !== null && $encodedResults['return'] !== null) {
                $this->assertEquals(
                    $originalResults['return'],
                    $encodedResults['return'],
                    "Return values differ between original and encoded file execution"
                );
            }

            // Log success for clarity
            $this->addToAssertionCount(1); // Add a "virtual" assertion for successful execution comparison
        } catch (SkippedTest $e) {
            // Re-throw PHPUnit skipped test exceptions
            throw $e;
        } catch (\Exception $e) {
            // Any other exception is a test failure
            $this->fail("Exception during file execution comparison: " . $e->getMessage());
        }
    }

    /**
     * Normalize output to remove irrelevant differences
     * 
     * @param string $output The output to normalize
     * @return string Normalized output
     */
    protected function normalizeOutput(string $output): string
    {
        // Remove timestamps (like "2025-05-05 12:34:56")
        $output = preg_replace('/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/', '[TIMESTAMP]', $output);

        // Remove memory usage reports
        $output = preg_replace('/Memory usage: \d+\.\d+ MB/', 'Memory usage: [MEM] MB', $output);

        // Remove execution time reports
        $output = preg_replace('/Execution time: \d+\.\d+ sec/', 'Execution time: [TIME] sec', $output);

        // Remove absolute file paths
        $output = preg_replace('/' . preg_quote(__DIR__, '/') . '\/[^\s]+/', '[PATH]', $output);

        // Remove any random hashes or IDs (basic detection of hex strings)
        $output = preg_replace('/[0-9a-f]{32}/', '[HASH]', $output);

        return $output;
    }
}
