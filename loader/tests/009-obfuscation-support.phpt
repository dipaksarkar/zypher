--TEST--
Zypher obfuscation support
--SKIPIF--
<?php
if (!extension_loaded('zypher')) echo 'skip zypher extension not available';
?>
--FILE--
<?php
/**
 * Test file for the Zypher obfuscation support
 * This test verifies that the obfuscation feature works correctly
 */

// Path to encoder
$encoderPath = dirname(__DIR__) . '/../encoder/encode.php';
if (!file_exists($encoderPath)) {
    die("Encoder not found at: $encoderPath\n");
}

// Create temporary files for the test
$testDir = sys_get_temp_dir() . '/zypher_test_' . uniqid();
if (!file_exists($testDir)) {
    mkdir($testDir, 0777, true);
}
$testFile = $testDir . '/obfuscation_test.php';
$encodedFile = $testDir . '/obfuscation_test_encoded.php';

echo "Zypher obfuscation test\n";
echo "======================\n\n";

// Create a test file with variables that should be obfuscated
file_put_contents($testFile, '<?php
$originalVariable = "Hello World";
$counter = 42;

function originalFunction() {
    $localVar = "I should be obfuscated";
    echo $localVar;
}

echo $originalVariable . " " . $counter . "\n";
originalFunction();
?>');

// Execute the encoder with the --obfuscate option
$command = sprintf('php "%s" "%s" "%s" --obfuscate --verbose 2>&1', 
    $encoderPath, $testFile, $encodedFile);

echo "Running encoder: " . $command . "\n";
$output = shell_exec($command);

echo "Encoder output:\n";
echo "---------------\n";
echo substr($output, 0, 500) . (strlen($output) > 500 ? "...[truncated]" : "") . "\n\n";

// Check if the encoded file was created
if (!file_exists($encodedFile)) {
    echo "FAILED: Encoded file was not created\n";
    exit(1);
}

// Check if the encoded file contains the original variable names
$encodedContent = file_get_contents($encodedFile);
$containsOriginalVar = strpos($encodedContent, '$originalVariable') !== false;
$containsObfuscatedContent = strpos($output, 'code obfuscation') !== false;

echo "Results:\n";
echo "--------\n";
echo "Encoded file created: " . (file_exists($encodedFile) ? "YES" : "NO") . "\n";
echo "Contains references to original variables: " . ($containsOriginalVar ? "YES" : "NO") . "\n";
echo "Evidence of obfuscation in output: " . ($containsObfuscatedContent ? "YES" : "NO") . "\n";

// Clean up
@unlink($testFile);
@unlink($encodedFile);
@rmdir($testDir);

echo "\nTest completed\n";
?>
--EXPECTF--
Zypher obfuscation test
======================

Running encoder: php "%s" "%s" "%s" --obfuscate --verbose %s
Encoder output:
---------------
%s

Results:
--------
Encoded file created: YES
Contains references to original variables: NO
Evidence of obfuscation in output: YES

Test completed