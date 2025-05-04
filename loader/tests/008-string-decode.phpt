--TEST--
Zypher string decoding functionality test
--SKIPIF--
<?php
if (!extension_loaded('zypher')) echo 'skip zypher extension not available';
if (!function_exists('zypher_decode_string')) echo 'skip zypher_decode_string function not available';
?>
--FILE--
<?php
/**
 * Test file for the Zypher string decoding functionality
 * This test verifies that the native string decoding function works properly with XOR encryption
 */

echo "Zypher string decoding test\n";
echo "===========================\n\n";

// Test data - Note: we're removing the % character from the special characters test to avoid test output issues
$test_strings = [
    'Hello World',
    'This is a test string for encryption',
    'Special characters: !@#$^&*()_+<>?:"{}',  // Removed % character
    'Numbers: 1234567890',
    'Unicode: 字符测试',
];

$key = 'test-key';
$key_hashed = md5($key);

echo "Using test key: $key (hashed: $key_hashed)\n\n";

$success_count = 0;
$failed = [];

foreach ($test_strings as $idx => $original) {
    // Manually encode the string (same algorithm as in the encoder)
    $encoded = '';
    $keyLen = strlen($key_hashed); // Use the hashed key for encoding
    for ($i = 0; $i < strlen($original); $i++) {
        $encoded .= chr(ord($original[$i]) ^ ord($key_hashed[$i % $keyLen]));
    }
    $hex = bin2hex($encoded);

    // Decode the string using the native function
    $decoded = zypher_decode_string($hex, $key_hashed);

    // Compare results
    $success = ($decoded === $original);
    if ($success) {
        $success_count++;
    } else {
        $failed[] = $original;
    }

    echo "Test #" . ($idx + 1) . ": ";
    echo $success ? "SUCCESS" : "FAILED";
    echo "\n";
    echo "  Original: '$original'\n";
    echo "  Decoded: '$decoded'\n";
}

echo "\nResults: $success_count of " . count($test_strings) . " tests passed\n";

if (count($failed) > 0) {
    echo "Failed strings:\n";
    foreach ($failed as $str) {
        echo "- '$str'\n";
    }
} else {
    echo "All tests passed successfully!\n";
}
?>
--EXPECTF--
Zypher string decoding test
===========================

Using test key: test-key (hashed: %s)

Test #1: SUCCESS
  Original: 'Hello World'
  Decoded: 'Hello World'
Test #2: SUCCESS
  Original: 'This is a test string for encryption'
  Decoded: 'This is a test string for encryption'
Test #3: SUCCESS
  Original: 'Special characters: !@#$^&*()_+<>?:"{}'
  Decoded: 'Special characters: !@#$^&*()_+<>?:"{}'
Test #4: SUCCESS
  Original: 'Numbers: 1234567890'
  Decoded: 'Numbers: 1234567890'
Test #5: SUCCESS
  Original: 'Unicode: 字符测试'
  Decoded: 'Unicode: 字符测试'

Results: 5 of 5 tests passed
All tests passed successfully!