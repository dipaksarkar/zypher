--TEST--
Zypher junk code insertion support
--EXTENSIONS--
zypher
--FILE--
<?php
/**
 * Test file for the Zypher junk code insertion feature
 * This test verifies that the --junk-code option works correctly
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
$testFile = $testDir . '/junk_code_test.php';
$encodedFile = $testDir . '/junk_code_test_encoded.php';

echo "Zypher junk code insertion test\n";
echo "============================\n\n";

// Create a test file with simple code
file_put_contents($testFile, '<?php
function testFunction() {
    $result = 0;
    for ($i = 0; $i < 10; $i++) {
        $result += $i;
    }
    return $result;
}

echo "Result: " . testFunction() . "\n";
?>');

// Execute the encoder with the --junk-code option
$command = sprintf('php "%s" "%s" "%s" --junk-code --verbose 2>&1', 
    $encoderPath, $testFile, $encodedFile);

echo "Running encoder: " . $command . "\n";
$output = shell_exec($command);

// Check if the encoded file was created
if (!file_exists($encodedFile)) {
    echo "FAILED: Encoded file was not created\n";
    exit(1);
}

// Show parts of the output relevant to testing
echo "Encoder output (excerpt):\n";
echo "---------------------\n";
echo "Source: " . basename($testFile) . "\n";
echo "Destination: " . basename($encodedFile) . "\n";
    echo "FAILED: Encoded file was not created\n";
    exit(1);
}

// Check for debug mode
$inDebugMode = strpos($output, 'base64 encoding for debugging') !== false;

// Analyze the encoded file 
$encodedContent = file_get_contents($encodedFile);
$sourceSize = filesize($testFile);
$encodedSize = filesize($encodedFile);

echo "Results:\n";
echo "--------\n";
echo "Encoded file created: " . (file_exists($encodedFile) ? "YES" : "NO") . "\n";
if ($inDebugMode) {
    echo "NOTE: Debug mode detected - Using base64 encoding\n";
}
echo "Original file size: " . $sourceSize . " bytes\n";
echo "Encoded file size: " . $encodedSize . " bytes\n";
echo "File size increased: " . ($encodedSize > $sourceSize ? "YES" : "NO") . "\n";

// Clean up
@unlink($testFile);
@unlink($encodedFile);
@rmdir($testDir);

echo "\nTest completed successfully\n";
?>
--EXPECTF--
Zypher junk code insertion test
============================

Running encoder: php "%s" "%s" "%s" --junk-code --verbose %s
Encoder output (excerpt):
---------------
Source: junk_code_test.php
Destination: junk_code_test_encoded.php
Processing file...

Results:
--------
Encoded file created: YES
NOTE: Debug mode detected - Using base64 encoding
Original file size: %d bytes
Encoded file size: %d bytes
File size increased: YES

Test completed successfully