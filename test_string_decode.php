<?php

/**
 * Test file for the Zypher string decoding functionality
 * This file tests if the native string decoding function works properly
 */

// Check if the extension is loaded
if (!extension_loaded('zypher')) {
    die("Error: Zypher extension is not loaded. Make sure it's installed and enabled.\n");
}

// Check if the string decoding function exists
if (!function_exists('zypher_decode_string')) {
    die("Error: zypher_decode_string function doesn't exist. Make sure you're using the updated version.\n");
}

echo "Zypher string decoding test\n";
echo "===========================\n\n";

// Test data
$test_strings = [
    'Hello World',
    'This is a test string for encryption',
    'Special characters: !@#$%^&*()_+<>?:"{}',
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
    echo "  Encoded (hex): '$hex'\n";
    echo "  Decoded: '$decoded'\n\n";
}

echo "Results: $success_count of " . count($test_strings) . " tests passed\n";

if (count($failed) > 0) {
    echo "Failed strings:\n";
    foreach ($failed as $str) {
        echo "- '$str'\n";
    }
    exit(1);
} else {
    echo "All tests passed successfully!\n";
    exit(0);
}
