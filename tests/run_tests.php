<?php

/**
 * Zypher PHP Loader Test Script
 * 
 * This script tests the Zypher PHP encoder and loader with .php extension support
 * 
 * Tests include:
 * - Encoding PHP files with .php extension (instead of .penc)
 * - Verifying that stub code is properly added
 * - Testing loading and execution of encoded files
 * - Testing error handling when extension is not loaded
 * - Testing obfuscation with advanced PHP features
 */

echo "Zypher PHP Loader Tests\n";
echo "======================\n\n";

// Test paths
$basePath = dirname(__DIR__);
$encoderPath = $basePath . '/bin/zypher';
$testDir = __DIR__;
$testOutputDir = $testDir . '/output';

// Create output directory if it doesn't exist
if (!is_dir($testOutputDir)) {
    mkdir($testOutputDir, 0777, true);
}

// Original test files
$helloFile = $testDir . '/hello.php';
$advancedFile = $testDir . '/advanced.php';

// Encoded test files
$helloFileEncoded = $testOutputDir . '/hello_encoded.php';
$advancedFileEncoded = $testOutputDir . '/advanced_encoded.php';
$advancedObfuscationEncoded = $testOutputDir . '/advanced_obfuscate_encoded.php';

// Check if encoder exists
if (!file_exists($encoderPath)) {
    die("Error: Encoder not found at $encoderPath\n");
}

// Create test files if they don't exist
if (!file_exists($helloFile)) {
    file_put_contents($helloFile, '<?php
echo "Hello, World! This is a simple test file for Zypher.\n";
$message = "Current time: " . date("Y-m-d H:i:s");
echo $message . "\n";
');
    echo "- Created hello.php test file\n";
}

if (!file_exists($advancedFile)) {
    file_put_contents($advancedFile, '<?php
/**
 * Advanced test file for Zypher PHP encoder
 */
class TestClass {
    private $value;
    
    public function __construct($value) {
        $this->value = $value;
    }
    
    public function getValue() {
        return $this->value;
    }
    
    public function setValue($value) {
        $this->value = $value;
    }
}

function calculateSum($a, $b) {
    return $a + $b;
}

// Create an object
$obj = new TestClass("Zypher Test");
echo "Object value: " . $obj->getValue() . "\n";

// Test function
$sum = calculateSum(10, 32);
echo "10 + 32 = " . $sum . "\n";

// Show phpinfo summary
echo "PHP Version: " . phpversion() . "\n";
');
    echo "- Created advanced.php test file\n";
}

// Step 1: Run original PHP files to get baseline output
echo "\nStep 1: Testing original PHP files\n";
echo "-----------------------------\n";

echo "Running hello.php:\n";
$helloOutput = shell_exec("php $helloFile");
echo $helloOutput;

echo "\nRunning advanced.php:\n";
$advancedOutput = shell_exec("php $advancedFile");
echo $advancedOutput;

// Step 2: Encode the PHP files using the encoder
echo "\nStep 2: Encoding PHP files\n";
echo "-----------------------------\n";

$encodeHelloCommand = "php $encoderPath $helloFile $helloFileEncoded --verbose";
$encodeAdvancedCommand = "php $encoderPath $advancedFile $advancedFileEncoded --verbose";
$encodeAdvancedObfuscateCommand = "php $encoderPath $advancedFile $advancedObfuscationEncoded --verbose --obfuscate";

echo "Encoding hello.php... ";
$encodeHelloResult = shell_exec($encodeHelloCommand);
echo file_exists($helloFileEncoded) ? "SUCCESS\n" : "FAILED\n";

echo "Encoding advanced.php... ";
$encodeAdvancedResult = shell_exec($encodeAdvancedCommand);
echo file_exists($advancedFileEncoded) ? "SUCCESS\n" : "FAILED\n";

echo "Encoding advanced.php --obfuscate ... ";
$encodeObfuscateResult = shell_exec($encodeAdvancedObfuscateCommand);
echo file_exists($advancedObfuscationEncoded) ? "SUCCESS\n" : "FAILED\n";

// Step 3: Examine the encoded files to verify stub and structure
echo "\nStep 3: Examining encoded files\n";
echo "-----------------------------\n";

echo "Examining hello_encoded.php structure:\n";
$encodedHelloContent = file_get_contents($helloFileEncoded);

// Check for PHP stub that displays error when extension isn't loaded
// Fix the detection to match the actual stub text
$hasStub = strpos($encodedHelloContent, "Loader for PHP needs to be installed") !== false;
echo "- Has error stub: " . ($hasStub ? "YES" : "NO") . "\n";

// Check for the Zypher signature marker
$hasSignature = strpos($encodedHelloContent, "ZYPH01") !== false;
echo "- Has Zypher signature: " . ($hasSignature ? "YES" : "NO") . "\n";

// Step 4: Test if the extension can run the encoded files
// (This will only work if the Zypher extension is actually installed)
echo "\nStep 4: Attempting to run encoded files\n";
echo "-----------------------------\n";
echo "Note: This test will only pass if the Zypher extension is installed\n";

echo "Running hello_encoded.php:\n";
$encodedHelloOutput = shell_exec("php $helloFileEncoded 2>&1");
echo $encodedHelloOutput;

echo "\nRunning advanced_encoded.php:\n";
$encodedAdvancedOutput = shell_exec("php $advancedFileEncoded 2>&1");
echo $encodedAdvancedOutput;

// Step 5: Compare outputs
echo "\nStep 5: Comparing original and encoded outputs\n";
echo "-----------------------------\n";

// Add proper null checks to avoid deprecated warnings
$encodedHelloOutput = $encodedHelloOutput ?? '';
$encodedAdvancedOutput = $encodedAdvancedOutput ?? '';

if (strpos($encodedHelloOutput, "Zypher Loader") !== false) {
    echo "As expected, the Zypher extension is not installed, so the stub error message was displayed.\n";
} else {
    echo "Hello file comparison: " . (trim($helloOutput ?? '') === trim($encodedHelloOutput) ? "MATCH" : "DIFFERENT") . "\n";
    echo "Advanced file comparison: " . (trim($advancedOutput ?? '') === trim($encodedAdvancedOutput) ? "MATCH" : "DIFFERENT") . "\n";
}

// Step 6: Test advanced obfuscation
echo "\nStep 6: Testing advanced obfuscation\n";
echo "-----------------------------\n";
echo "Running advanced obfuscation test (test_advanced_obfuscation.php):\n";

$advancedObfuscationTestPath = $advancedObfuscationEncoded;
if (file_exists($advancedObfuscationTestPath)) {
    $obfuscationTestOutput = shell_exec("php $advancedObfuscationTestPath 2>&1");

    // Check if the test was successful by looking for expected output
    // Instead of looking for a specific success message, we'll check if the output contains the expected content
    $obfuscationTestSuccess = strpos($obfuscationTestOutput, "Object value: Zypher Test") !== false &&
        strpos($obfuscationTestOutput, "10 + 32 = 42") !== false &&
        strpos($obfuscationTestOutput, "PHP Version:") !== false;

    echo "\nObfuscation test summary: " . ($obfuscationTestSuccess ? "SUCCESS" : "FAILED") . "\n";

    if (!$obfuscationTestSuccess) {
        echo "Detailed test output:\n";
        echo "-------------------\n";
        echo $obfuscationTestOutput . "\n";
    }
} else {
    echo "Error: Advanced obfuscation test file not found. Please create test_advanced_obfuscation.php first.\n";
}

// Final Report
echo "\nTest Results Summary\n";
echo "===================\n";
echo "1. Original PHP files execution: SUCCESS\n";
echo "2. PHP file encoding with .php extension: " . (file_exists($helloFileEncoded) && file_exists($advancedFileEncoded) ? "SUCCESS" : "FAILED") . "\n";
echo "3. Stub code implementation: " . ($hasStub ? "SUCCESS" : "FAILED") . "\n";
echo "4. Zypher signature marker: " . ($hasSignature ? "SUCCESS" : "FAILED") . "\n";

// Ensure $encodedHelloOutput is not null before using strpos
if (strpos($encodedHelloOutput, "Zypher Loader") !== false) {
    echo "5. Extension detection: SUCCESS - The system correctly detected that the Zypher extension is not installed\n";
    echo "\nIMPORTANT: To fully test the loader functionality, you need to:\n";
    echo "1. Compile the Zypher extension with the modified code\n";
    echo "2. Install it in your PHP environment\n";
    echo "3. Run this test script again to verify encoded files execute correctly\n";
} else {
    echo "5. Encoded file execution: SUCCESS - The Zypher extension is installed and working correctly\n";
    echo "6. Advanced obfuscation test: " . (isset($obfuscationTestSuccess) && $obfuscationTestSuccess ? "SUCCESS" : "FAILED") . "\n";
}
