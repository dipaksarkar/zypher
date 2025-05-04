<?php

/**
 * Zypher Security Test
 * 
 * This file tests the enhanced security features of the Zypher encoder/loader system,
 * specifically testing the two-layer encryption with HMAC-based key derivation.
 */

echo "Zypher Security Test\n";
echo "====================\n\n";

// Test message that will be encoded and then loaded with our extension
echo "Original Message: Hello, this is a secure message protected with enhanced Zypher encryption!\n";

// Additional information that could be used in commercial licensing
echo "Current timestamp: " . date('Y-m-d H:i:s') . "\n";
echo "Server name: " . php_uname('n') . "\n";

// Create a unique identifier (could be used for license validation)
$unique_id = md5(uniqid(mt_rand(), true));
echo "Unique ID: $unique_id\n";

// Perform some computation to verify code execution
$computation_result = 0;
for ($i = 1; $i <= 10; $i++) {
    $computation_result += $i * $i;
}
echo "Computation result: $computation_result\n";

echo "\nIf you can see this message after encoding and running the encoded file,\n";
echo "it means the enhanced encryption with HMAC-SHA256 key derivation is working correctly!\n";
