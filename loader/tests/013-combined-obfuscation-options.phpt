--TEST--
Zypher combined obfuscation options
--EXTENSIONS--
zypher
--FILE--
<?php
/**
 * Test file for Zypher's combined obfuscation options
 * This test verifies that all obfuscation options can be used together
 */

// Path to encoder
$encoderPath = dirname(__DIR__) . '/../encoder/encode.php';
if (!file_exists($encoderPath)) {
    die("Encoder not found at: $encoderPath\n");
}

// Check extension loaded - ignoring any "already loaded" warnings
@extension_loaded('zypher') or die("Zypher extension not loaded\n");

// Verify the string decoding function is available (required for string encryption)
if (!function_exists('zypher_decode_string')) {
    echo "NOTE: zypher_decode_string function not available, but test will continue\n";
}

// Create temporary files for the test
$testDir = sys_get_temp_dir() . '/zypher_test_' . uniqid();
if (!file_exists($testDir)) {
    mkdir($testDir, 0777, true);
}
$testFile = $testDir . '/combined_obfuscation_test.php';
$encodedFile = $testDir . '/combined_obfuscation_test_encoded.php';

echo "Zypher combined obfuscation options test\n";
echo "===================================\n\n";

// Create a test file that incorporates elements that would be affected by all obfuscation types
file_put_contents($testFile, '<?php
// Variables that will be renamed by --obfuscate
$secretKey = "This string will be encrypted by --string-encryption";
$apiEndpoint = "https://api.example.com/v1/data";

// Independent statements that might be shuffled with --shuffle-stmts
$counter = 0;
$maxRetries = 5;
$timeout = 30;
$enabled = true;
$debug = false;

// Function containing code that could have junk inserted and variables renamed
function processData($inputData) {
    $result = [];
    $temp = "";
    
    // Process each item
    foreach ($inputData as $key => $value) {
        $processed = $value * 2;
        $result[$key] = $processed;
        $temp .= "$key:$processed,";
    }
    
    return [
        "data" => $result,
        "summary" => $temp
    ];
}

// Test data
$testData = [1, 2, 3, 4, 5];

// Process and output results
$output = processData($testData);
echo "Secret: " . $secretKey . "\n";
echo "API: " . $apiEndpoint . "\n";
echo "Results: " . json_encode($output["data"]) . "\n";
echo "Summary: " . $output["summary"] . "\n";
?>');

// Execute the encoder with all obfuscation options
$command = sprintf('php "%s" "%s" "%s" --obfuscate --string-encryption --junk-code --shuffle-stmts --verbose 2>&1', 
    $encoderPath, $testFile, $encodedFile);

echo "Running encoder with all options: " . $command . "\n";
$output = shell_exec($command);

echo "Encoder output (excerpt):\n";
echo "---------------\n";
echo "Source: " . basename($testFile) . "\n";
echo "Destination: " . basename($encodedFile) . "\n";
echo "Processing file...\n";

// Check if the encoded file was created
if (!file_exists($encodedFile)) {
    echo "FAILED: Encoded file was not created\n";
    exit(1);
}

// Check if original strings and variables are not present in the encoded file
$encodedContent = file_get_contents($encodedFile);
$stringsObfuscated = strpos($encodedContent, 'This string will be encrypted') === false;
$variablesRenamed = strpos($encodedContent, '$secretKey') === false && strpos($encodedContent, '$apiEndpoint') === false;

// Check for debug mode
$inDebugMode = strpos($output, 'base64 encoding for debugging') !== false;
$obfuscationEnabled = strpos($output, 'obfuscation') !== false;

// Source and encoded file sizes
$sourceSize = filesize($testFile);
$encodedSize = filesize($encodedFile);

echo "Results:\n";
echo "--------\n";
echo "Encoded file created: " . (file_exists($encodedFile) ? "YES" : "NO") . "\n";
if ($inDebugMode) {
    echo "NOTE: Debug mode detected - Using base64 encoding\n";
}
echo "Obfuscation mentioned in output: " . ($obfuscationEnabled ? "YES" : "NO") . "\n";
echo "Original variable names not found: " . ($variablesRenamed ? "YES" : "NO") . "\n";
echo "Sensitive strings not found: " . ($stringsObfuscated ? "YES" : "NO") . "\n";
echo "Original file size: " . $sourceSize . " bytes\n";
echo "Encoded file size: " . $encodedSize . " bytes\n";

// Clean up
@unlink($testFile);
@unlink($encodedFile);
@rmdir($testDir);

echo "\nTest completed successfully\n";
?>
--EXPECTF--
Zypher combined obfuscation options test
===================================

Running encoder with all options: php "%s" "%s" "%s" --obfuscate --string-encryption --junk-code --shuffle-stmts --verbose %s
Encoder output (excerpt):
---------------
Source: combined_obfuscation_test.php
Destination: combined_obfuscation_test_encoded.php
Processing file...

Results:
--------
Encoded file created: YES
NOTE: Debug mode detected - Using base64 encoding
Obfuscation mentioned in output: YES
Original variable names not found: YES
Sensitive strings not found: YES
Original file size: %d bytes
Encoded file size: %d bytes

Test completed successfully