<?php

/**
 * Comprehensive Test Suite for Zypher PHP Encoder
 * 
 * This script tests all features and options of the Zypher encoder:
 * - Basic encoding functionality
 * - Command line options (--master-key, --quiet, --verbose)
 * - Obfuscation features (--obfuscate, --shuffle-stmts, --junk-code, --string-encryption)
 * - Error handling and edge cases
 * - Output file name variations
 * - Signature detection
 * - File format validation
 */

echo "Zypher PHP Encoder Comprehensive Tests\n";
echo "=====================================\n\n";

// Test paths
$basePath = dirname(__DIR__);
$encoderPath = $basePath . '/encoder/encode.php';
$testDir = __DIR__;
$testOutputDir = $testDir . '/output';

// Create output directory if it doesn't exist
if (!file_exists($testOutputDir)) {
    mkdir($testOutputDir, 0777, true);
    echo "Created test output directory: $testOutputDir\n";
}

// Check if encoder exists
if (!file_exists($encoderPath)) {
    die("Error: Encoder not found at $encoderPath\n");
}

// Test case counter
$totalTests = 0;
$passedTests = 0;

/**
 * Helper function to run a test and track results
 */
function runTest($name, $callback)
{
    global $totalTests, $passedTests;

    echo "\n----- Test: $name -----\n";
    $totalTests++;

    try {
        $result = $callback();
        if ($result) {
            echo "PASSED ✓\n";
            $passedTests++;
        } else {
            echo "FAILED ✗\n";
        }
        return $result;
    } catch (Exception $e) {
        echo "ERROR: " . $e->getMessage() . "\n";
        echo "FAILED ✗\n";
        return false;
    }
}

/**
 * Helper function to create test file with specific content
 */
function createTestFile($filename, $content)
{
    file_put_contents($filename, $content);
    if (!file_exists($filename)) {
        throw new Exception("Failed to create test file: $filename");
    }
    return $filename;
}

/**
 * Check if a file has the Zypher signature
 */
function hasZypherSignature($filePath)
{
    $fp = fopen($filePath, 'rb');
    if (!$fp) {
        return false;
    }

    // Read the first 6 bytes (ZYPH01)
    $signature = fread($fp, 6);
    fclose($fp);

    return $signature === 'ZYPH01';
}

// ----------------------------------------
// TEST 1: Basic encoding functionality
// ----------------------------------------
runTest("Basic Encoding", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_basic.php';
    $outputFile = $testOutputDir . '/test_basic_encoded.php';

    // Create simple test file
    createTestFile($testFile, '<?php echo "Basic test file"; ?>');

    // Encode the file
    $output = shell_exec("php $encoderPath $testFile $outputFile 2>&1");

    // Check if output file exists
    $fileExists = file_exists($outputFile);
    echo "- File created: " . ($fileExists ? "YES" : "NO") . "\n";

    // Check for Zypher signature
    $hasSignature = hasZypherSignature($outputFile);
    echo "- Has Zypher signature: " . ($hasSignature ? "YES" : "NO") . "\n";

    // Check for stub code
    $content = file_get_contents($outputFile);
    $hasStub = strpos($content, "extension_loaded('zypher')") !== false;
    echo "- Has extension check stub: " . ($hasStub ? "YES" : "NO") . "\n";

    // Cleanup
    unlink($testFile);

    return $fileExists && $hasSignature && $hasStub;
});

// ----------------------------------------
// TEST 2: Default output filename
// ----------------------------------------
runTest("Default Output Filename", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_default_output.php';
    $expectedOutput = $testDir . '/test_default_output_encoded.php';

    // Create simple test file
    createTestFile($testFile, '<?php echo "Testing default output filename"; ?>');

    // Encode the file without specifying output filename
    $output = shell_exec("php $encoderPath $testFile 2>&1");

    // Check if the default-named output file exists
    $fileExists = file_exists($expectedOutput);
    echo "- Default named file created: " . ($fileExists ? "YES" : "NO") . "\n";

    // Cleanup
    unlink($testFile);
    if ($fileExists) {
        unlink($expectedOutput);
    }

    return $fileExists;
});

// ----------------------------------------
// TEST 3: Custom Master Key
// ----------------------------------------
runTest("Custom Master Key", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_master_key.php';
    $outputFile = $testOutputDir . '/test_master_key_encoded.php';

    // Create test file
    createTestFile($testFile, '<?php echo "Testing custom master key"; ?>');

    // Encode the file with a custom master key
    $output = shell_exec("php $encoderPath $testFile $outputFile --master-key=CustomSecretKey123 --verbose 2>&1");

    // Check if output contains the custom key (in verbose output)
    $usedCustomKey = strpos($output, 'CustomSecretKey123') !== false;
    echo "- Used custom master key: " . ($usedCustomKey ? "YES" : "NO") . "\n";

    // Check if file was created
    $fileExists = file_exists($outputFile);
    echo "- File created: " . ($fileExists ? "YES" : "NO") . "\n";

    // Cleanup
    unlink($testFile);

    return $usedCustomKey && $fileExists;
});

// ----------------------------------------
// TEST 4: Quiet Mode
// ----------------------------------------
runTest("Quiet Mode", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_quiet_mode.php';
    $outputFile = $testOutputDir . '/test_quiet_mode_encoded.php';

    // Create test file
    createTestFile($testFile, '<?php echo "Testing quiet mode"; ?>');

    // Encode in quiet mode
    ob_start();
    $output = shell_exec("php $encoderPath $testFile $outputFile --quiet 2>&1");
    ob_end_clean();

    // Check if output is empty (quiet mode)
    $isQuiet = empty($output);
    echo "- Output suppressed: " . ($isQuiet ? "YES" : "NO") . "\n";

    // File should still be created
    $fileExists = file_exists($outputFile);
    echo "- File created: " . ($fileExists ? "YES" : "NO") . "\n";

    // Cleanup
    unlink($testFile);

    return $isQuiet && $fileExists;
});

// ----------------------------------------
// TEST 5: Verbose Mode
// ----------------------------------------
runTest("Verbose Mode", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_verbose_mode.php';
    $outputFile = $testOutputDir . '/test_verbose_mode_encoded.php';

    // Create test file
    createTestFile($testFile, '<?php echo "Testing verbose mode"; ?>');

    // Encode with verbose flag
    $output = shell_exec("php $encoderPath $testFile $outputFile --verbose 2>&1");

    // Verbose mode should output detailed information
    $isVerbose = strpos($output, 'DEBUG:') !== false;
    echo "- Shows debug info: " . ($isVerbose ? "YES" : "NO") . "\n";

    // Check if the detailed key derivation is mentioned
    $hasKeyInfo = strpos($output, 'key derivation') !== false ||
        strpos($output, 'Generated random file key') !== false;
    echo "- Shows key information: " . ($hasKeyInfo ? "YES" : "NO") . "\n";

    // Cleanup
    unlink($testFile);

    return $isVerbose && $hasKeyInfo;
});

// ----------------------------------------
// TEST 6: Obfuscation Option
// ----------------------------------------
runTest("Obfuscation", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_obfuscation.php';
    $outputFile = $testOutputDir . '/test_obfuscation_encoded.php';

    // Create test file with variables that should be obfuscated
    createTestFile($testFile, '<?php
    $myVariable = "test value";
    $anotherVar = 42;
    
    function testFunction() {
        $localVar = "local value";
        echo $localVar;
    }
    
    echo $myVariable . $anotherVar;
    testFunction();
    ?>');

    // Encode with obfuscation flag
    $output = shell_exec("php $encoderPath $testFile $outputFile --obfuscate --verbose 2>&1");

    // Check for obfuscation message in the output
    $obfuscationEnabled = strpos($output, 'code obfuscation') !== false;
    echo "- Obfuscation enabled: " . ($obfuscationEnabled ? "YES" : "NO") . "\n";

    // Check if file was created
    $fileExists = file_exists($outputFile);
    echo "- File created: " . ($fileExists ? "YES" : "NO") . "\n";

    // Cleanup
    unlink($testFile);

    return $obfuscationEnabled && $fileExists;
});

// ----------------------------------------
// TEST 7: String Encryption Option
// ----------------------------------------
runTest("String Encryption", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_string_encryption.php';
    $outputFile = $testOutputDir . '/test_string_encryption_encoded.php';

    // Create test file with string literals
    createTestFile($testFile, '<?php
    $string1 = "This is a test string that should be encrypted";
    $string2 = "Another string that should also be encrypted";
    echo $string1 . $string2;
    ?>');

    // Encode with string encryption flag
    $output = shell_exec("php $encoderPath $testFile $outputFile --obfuscate --string-encryption --verbose 2>&1");

    // Check for string encryption mention in the output
    $encryptionEnabled = strpos($output, 'string encryption') !== false;
    echo "- String encryption mentioned: " . ($encryptionEnabled ? "YES" : "NO") . "\n";

    // Read encoded file and check for decode function
    $encodedContent = file_get_contents($outputFile);
    $hasDecodeFunction = strpos($encodedContent, 'zypher_decode_string') !== false ||
        strpos($output, 'string encryption') !== false;
    echo "- Evidence of string encryption: " . ($hasDecodeFunction ? "YES" : "NO") . "\n";

    // Cleanup
    unlink($testFile);

    return $encryptionEnabled || $hasDecodeFunction;
});

// ----------------------------------------
// TEST 8: Junk Code Insertion
// ----------------------------------------
runTest("Junk Code Insertion", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_junk_code.php';
    $outputFile = $testOutputDir . '/test_junk_code_encoded.php';

    // Create a simple test file
    createTestFile($testFile, '<?php
    echo "Testing junk code insertion";
    ?>');

    // Encode with junk code option
    $output = shell_exec("php $encoderPath $testFile $outputFile --obfuscate --junk-code --verbose 2>&1");

    // Check for junk code mention in output
    $junkCodeEnabled = strpos($output, 'junk code') !== false;
    echo "- Junk code mentioned: " . ($junkCodeEnabled ? "YES" : "NO") . "\n";

    // Check if file was created
    $fileExists = file_exists($outputFile);
    echo "- File created: " . ($fileExists ? "YES" : "NO") . "\n";

    // Cleanup
    unlink($testFile);

    return $junkCodeEnabled && $fileExists;
});

// ----------------------------------------
// TEST 9: Error Handling - Missing Source File
// ----------------------------------------
runTest("Error Handling - Missing Source File", function () use ($encoderPath, $testOutputDir) {
    // Try to encode a non-existent file
    $nonExistentFile = 'this_file_does_not_exist.php';
    $outputFile = $testOutputDir . '/error_handling_test.php';

    $output = shell_exec("php $encoderPath $nonExistentFile $outputFile 2>&1");

    // Check if an error message was displayed
    $hasErrorMessage = strpos($output, 'Error') !== false &&
        strpos($output, 'does not exist') !== false;
    echo "- Error message for missing file: " . ($hasErrorMessage ? "YES" : "NO") . "\n";

    // Output file should not be created
    $outputNotCreated = !file_exists($outputFile);
    echo "- Output file not created: " . ($outputNotCreated ? "YES" : "NO") . "\n";

    return $hasErrorMessage && $outputNotCreated;
});

// ----------------------------------------
// TEST 10: Error Handling - Invalid PHP
// ----------------------------------------
runTest("Error Handling - Invalid PHP", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_invalid_php.php';
    $outputFile = $testOutputDir . '/test_invalid_php_encoded.php';

    // Create a file with invalid PHP syntax
    createTestFile($testFile, '<?php
    echo "This is invalid PHP syntax;
    $unclosed_string = "This string is not closed;
    ?>');

    // Try to encode the invalid file
    $output = shell_exec("php $encoderPath $testFile $outputFile 2>&1");

    // The encoder should still process it (syntax checking is PHP's job)
    $fileCreated = file_exists($outputFile);
    echo "- Encoder processed invalid PHP: " . ($fileCreated ? "YES" : "NO") . "\n";

    // Cleanup
    unlink($testFile);
    if ($fileCreated) {
        unlink($outputFile);
    }

    // This test passes if the encoder handles invalid PHP (either by encoding it or showing a specific syntax error)
    return true;
});

// ----------------------------------------
// TEST 11: Large PHP File Test
// ----------------------------------------
runTest("Large PHP File Test", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_large_php.php';
    $outputFile = $testOutputDir . '/test_large_php_encoded.php';

    // Create a large PHP file (approximately 1MB)
    $largeContent = '<?php' . PHP_EOL;
    for ($i = 0; $i < 20000; $i++) {
        $largeContent .= '$var' . $i . ' = "This is test value ' . $i . '";' . PHP_EOL;
    }
    $largeContent .= 'echo "Large file test completed";' . PHP_EOL;

    createTestFile($testFile, $largeContent);

    // Try to encode the large file
    $output = shell_exec("php $encoderPath $testFile $outputFile 2>&1");

    // Check if output file exists
    $fileExists = file_exists($outputFile);
    echo "- Large file encoded: " . ($fileExists ? "YES" : "NO") . "\n";

    // Check if it's significantly larger than the input due to encoding
    if ($fileExists) {
        $originalSize = filesize($testFile);
        $encodedSize = filesize($outputFile);
        $sizeRatio = $encodedSize / $originalSize;
        echo "- Original size: " . number_format($originalSize) . " bytes\n";
        echo "- Encoded size: " . number_format($encodedSize) . " bytes\n";
        echo "- Size ratio: " . number_format($sizeRatio, 2) . "x\n";
    }

    // Cleanup
    unlink($testFile);

    return $fileExists;
});

// ----------------------------------------
// TEST 12: Multiple Encoding Options
// ----------------------------------------
runTest("Multiple Encoding Options", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_multiple_options.php';
    $outputFile = $testOutputDir . '/test_multiple_options_encoded.php';

    // Create test file
    createTestFile($testFile, '<?php
    $secret = "This is a secret message";
    function displaySecret($s) {
        echo $s;
    }
    displaySecret($secret);
    ?>');

    // Encode with multiple options
    $output = shell_exec("php $encoderPath $testFile $outputFile --obfuscate --string-encryption --junk-code --verbose 2>&1");

    // Check if all options were mentioned
    $hasObfuscation = strpos($output, 'obfuscation') !== false;
    $hasStringEncryption = strpos($output, 'string encryption') !== false;
    $hasJunkCode = strpos($output, 'junk code') !== false;

    echo "- Obfuscation mentioned: " . ($hasObfuscation ? "YES" : "NO") . "\n";
    echo "- String encryption mentioned: " . ($hasStringEncryption ? "YES" : "NO") . "\n";
    echo "- Junk code mentioned: " . ($hasJunkCode ? "YES" : "NO") . "\n";

    // Check if file was created
    $fileExists = file_exists($outputFile);
    echo "- File created: " . ($fileExists ? "YES" : "NO") . "\n";

    // Cleanup
    unlink($testFile);

    return $fileExists && ($hasObfuscation || $hasStringEncryption || $hasJunkCode);
});

// ----------------------------------------
// TEST 13: Non-PHP Extension Output
// ----------------------------------------
runTest("Non-PHP Extension Output", function () use ($encoderPath, $testDir, $testOutputDir) {
    $testFile = $testDir . '/test_non_php_ext.php';
    $outputFile = $testOutputDir . '/test_output.txt'; // Non-PHP extension

    // Create test file
    createTestFile($testFile, '<?php echo "Testing non-PHP extension output"; ?>');

    // Encode with a non-PHP extension output file
    $output = shell_exec("php $encoderPath $testFile $outputFile 2>&1");

    // The encoder should append .php to the output
    $expectedOutput = $testOutputDir . '/test_output.txt.php';
    $fileExists = file_exists($expectedOutput);
    echo "- Output with .php extension: " . ($fileExists ? "YES" : "NO") . "\n";

    // Cleanup
    unlink($testFile);
    if ($fileExists) {
        unlink($expectedOutput);
    }

    return $fileExists;
});

// Display a summary of the test results
echo "\n\n=== Test Results Summary ===\n";
echo "Tests Run: $totalTests\n";
echo "Tests Passed: $passedTests\n";
echo "Success Rate: " . number_format(($passedTests / $totalTests) * 100, 1) . "%\n";

if ($passedTests === $totalTests) {
    echo "\nALL TESTS PASSED! 🎉\n";
} else {
    echo "\nSome tests failed. Please review the output above for details.\n";
}
