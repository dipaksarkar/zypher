<?php

/**
 * Zypher PHP Encoder Signature Detection Test
 * 
 * This test specifically focuses on the signature detection capabilities
 * of the Zypher encoder/loader system.
 * 
 * It tests:
 * 1. Creating encoded files with the proper ZYPH01 signature
 * 2. Detecting signatures in files
 * 3. Handling files with invalid/missing signatures
 * 4. Ensuring the extension correctly validates signatures
 */

// Path setup
$basePath = dirname(__DIR__);
$encoderPath = $basePath . '/bin/zypher';
$testDir = __DIR__;
$testOutputDir = $testDir . '/output';

// Create output directory if needed
if (!file_exists($testOutputDir)) {
    mkdir($testOutputDir, 0777, true);
    echo "Created test output directory: $testOutputDir\n";
}

// Function to check if a file has the Zypher signature
function has_zypher_signature($file)
{
    if (!file_exists($file)) {
        return false;
    }

    $fp = fopen($file, 'rb');
    if (!$fp) {
        return false;
    }

    // Read the first 6 bytes (ZYPH01)
    $signature = fread($fp, 6);
    fclose($fp);

    return $signature === 'ZYPH01';
}

echo "Zypher Signature Detection Tests\n";
echo "==============================\n\n";

// Test 1: Create a properly encoded file and verify signature
echo "Test 1: Encoding file and verifying signature\n";
$testFile = $testDir . '/test_signature.php';
$encodedFile = $testOutputDir . '/test_signature_encoded.php';

// Create a simple test file
file_put_contents($testFile, '<?php echo "Testing signature detection"; ?>');

// Encode the file
echo "Encoding file... ";
$output = shell_exec("php $encoderPath $testFile $encodedFile 2>&1");
echo "done\n";

// Check for proper signature
echo "Checking for Zypher signature... ";
if (has_zypher_signature($encodedFile)) {
    echo "FOUND ✓\n";
    $test1_passed = true;
} else {
    echo "NOT FOUND ✗\n";
    echo "Error: Encoded file does not have the proper ZYPH01 signature\n";
    $test1_passed = false;
}

// Test 2: Create a file with an invalid signature and verify detection
echo "\nTest 2: Testing invalid signature detection\n";
$invalidFile = $testOutputDir . '/invalid_signature.php';

// Create a file with an invalid signature (similar but not exactly ZYPH01)
$stubContent = '<?php 
if(!extension_loaded(\'zypher\')){die(\'The file \'.__FILE__." is corrupted.\\n\");}
echo("\\nError: Zypher extension not loaded\\n");
exit(199);
?>';

$invalidSignature = 'ZYP001'; // Incorrect signature
$encodedContent = base64_encode('This is not a valid Zypher encoded content');

file_put_contents($invalidFile, $stubContent . $invalidSignature . $encodedContent);

// Check for proper signature - should fail
echo "Checking invalid file for Zypher signature... ";
if (!has_zypher_signature($invalidFile)) {
    echo "CORRECTLY REJECTED ✓\n";
    $test2_passed = true;
} else {
    echo "INCORRECTLY ACCEPTED ✗\n";
    echo "Error: Invalid signature was incorrectly identified as valid\n";
    $test2_passed = false;
}

// Test 3: Create a file with a completely missing signature
echo "\nTest 3: Testing missing signature detection\n";
$missingFile = $testOutputDir . '/missing_signature.php';

// Create a file with no signature at all
file_put_contents($missingFile, $stubContent . base64_encode('No signature at all'));

// Check for proper signature - should fail
echo "Checking file with missing signature... ";
if (!has_zypher_signature($missingFile)) {
    echo "CORRECTLY REJECTED ✓\n";
    $test3_passed = true;
} else {
    echo "INCORRECTLY ACCEPTED ✗\n";
    echo "Error: File with no signature was incorrectly identified as valid\n";
    $test3_passed = false;
}

// Test 4: Attempt to execute the files and check behavior
// Note: This will only work if the Zypher extension is actually installed
echo "\nTest 4: Execution behavior with valid/invalid signatures\n";
echo "Note: Test is informational only if the extension isn't installed\n";

echo "Executing properly encoded file:\n";
$validOutput = shell_exec("php $encodedFile 2>&1");
$validResult = strpos($validOutput, "Zypher Loader") !== false ? "Extension not installed (expected error)" : "Execution succeeded";
echo "Result: $validResult\n";

echo "\nExecuting file with invalid signature:\n";
$invalidOutput = shell_exec("php $invalidFile 2>&1");
// Should show PHP errors regardless of extension being installed
$invalidResult = strpos($invalidOutput, "Error") !== false ? "Error detected (good)" : "No error (unexpected)";
echo "Result: $invalidResult\n";

echo "\nExecuting file with missing signature:\n";
$missingOutput = shell_exec("php $missingFile 2>&1");
// Should show PHP errors regardless of extension being installed
$missingResult = strpos($missingOutput, "Error") !== false ? "Error detected (good)" : "No error (unexpected)";
echo "Result: $missingResult\n";

// Clean up
unlink($testFile);
echo "\nCleaning up test files\n";

// Results summary
echo "\nTest Results\n";
echo "===========\n";
echo "Test 1 (Valid Signature): " . ($test1_passed ? "PASSED ✓" : "FAILED ✗") . "\n";
echo "Test 2 (Invalid Signature): " . ($test2_passed ? "PASSED ✓" : "FAILED ✗") . "\n";
echo "Test 3 (Missing Signature): " . ($test3_passed ? "PASSED ✓" : "FAILED ✗") . "\n";

$allPassed = $test1_passed && $test2_passed && $test3_passed;

echo "\nOverall result: " . ($allPassed ? "ALL TESTS PASSED ✓" : "TESTS FAILED ✗") . "\n";

if (!$allPassed) {
    echo "\nThe signature detection or application process might have issues. Please review the encoder code.\n";
}
