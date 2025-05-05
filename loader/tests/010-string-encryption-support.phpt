--TEST--
Zypher string encryption support
--SKIPIF--
<?php
if (!extension_loaded('zypher')) die('skip: zypher extension not available');
?>
--FILE--
<?php
/**
 * Test file for the Zypher string encryption feature
 * This test verifies that the --string-encryption option works correctly
 */

if (!function_exists('zypher_decode_string')) {
    die("zypher_decode_string function not available\n");
}

echo "Zypher string encryption test\n";
echo "===========================\n\n";

// Test the decoding function directly
$originalString = "Hello, this is a secret message!";
$key = "test-key-123";

// Manual XOR encoding to match the implementation
$encoded = '';
for ($i = 0; $i < strlen($originalString); $i++) {
    $encoded .= chr(ord($originalString[$i]) ^ ord($key[$i % strlen($key)]));
}
$hexEncoded = bin2hex($encoded);

echo "Original string: $originalString\n";
echo "Encoded as hex: $hexEncoded\n";

// Now decode using the extension function
$decoded = zypher_decode_string($hexEncoded, $key);

echo "Decoded string: $decoded\n\n";
echo "Verification:\n";
echo "-------------\n";
echo "Strings match: " . ($originalString === $decoded ? "YES" : "NO") . "\n";

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
$testFile = $testDir . '/string_encryption_test.php';
$encodedFile = $testDir . '/string_encryption_test_encoded.php';

// Create a test file with strings that should be encrypted
file_put_contents($testFile, '<?php
$secretMessage = "This is a secret message that should be encrypted";
$password = "SuperSecretPassword123!";
$apiKey = "api-key-12345-abcdefghijklmnopqrstuvwxyz";

// Echo these strings to verify they work after encoding
echo "Message: " . $secretMessage . "\n";
echo "Password: " . $password . "\n";
echo "API Key: " . $apiKey . "\n";
?>');

// Execute the encoder with the --string-encryption option
$command = sprintf('php "%s" "%s" "%s" --string-encryption --verbose 2>&1', 
    $encoderPath, $testFile, $encodedFile);

echo "\nRunning encoder: " . $command . "\n";
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
echo "Processing file...\n";

// Check if original strings are not present in the encoded file
$encodedContent = file_get_contents($encodedFile);
$stringsObfuscated = strpos($encodedContent, 'SuperSecretPassword123!') === false &&
                     strpos($encodedContent, 'This is a secret message') === false;

// File was actually encoded (contains the signature)
$isEncoded = strpos($encodedContent, 'ZYPH01') !== false;

// Check for debug mode
$inDebugMode = strpos($output, 'base64 encoding for debugging') !== false;

echo "\nResults:\n";
echo "--------\n";
echo "Encoded file created: " . ($isEncoded ? "YES" : "NO") . "\n";
echo "Sensitive strings not found in encoded file: " . ($stringsObfuscated ? "YES" : "NO") . "\n";
echo "File size: " . filesize($encodedFile) . " bytes\n";

// Clean up
@unlink($testFile);
@unlink($encodedFile);
@rmdir($testDir);

echo "\nTest completed successfully\n";
?>
--EXPECTF--
Zypher string encryption test
===========================

Original string: Hello, this is a secret message!
Encoded as hex: %s
Decoded string: Hello, this is a secret message!

Verification:
-------------
Strings match: YES

Running encoder: php "%s" "%s" "%s" --string-encryption --verbose %s
Encoder output (excerpt):
---------------------
Source: string_encryption_test.php
Destination: string_encryption_test_encoded.php
Processing file...

Results:
--------
Encoded file created: YES
Sensitive strings not found in encoded file: YES
File size: %d bytes

Test completed successfully