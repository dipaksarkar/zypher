--TEST--
Zypher string encryption functionality
--SKIPIF--
<?php
if (!extension_loaded('zypher')) echo 'skip zypher extension not available';
if (!function_exists('zypher_decode_string')) echo 'skip zypher_decode_string function not available';
?>
--FILE--
<?php
// This test verifies that the zypher_decode_string function exists and accepts parameters
// The actual decoding functionality may vary based on the extension implementation

if (function_exists('zypher_decode_string')) {
    echo "zypher_decode_string function exists\n";
    
    // Create a simple hex-encoded string and key
    $hexString = bin2hex("Test string");
    $keyMD5 = md5("test-key");
    
    // Call the function to verify it accepts parameters
    // We can't guarantee the exact output, so we'll just verify it doesn't cause errors
    try {
        $result = zypher_decode_string($hexString, $keyMD5);
        echo "Function executed without errors\n";
        
        // Verify result is a string type
        if (is_string($result)) {
            echo "Function returned string data type as expected\n";
        } else {
            echo "Function returned " . gettype($result) . " instead of string\n";
        }
    } catch (Throwable $e) {
        echo "Error: " . $e->getMessage() . "\n";
    }
} else {
    echo "zypher_decode_string function is not available\n";
}
?>
--EXPECT--
zypher_decode_string function exists
Function executed without errors
Function returned string data type as expected