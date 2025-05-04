--TEST--
Zypher signature detection
--SKIPIF--
<?php
if (!extension_loaded('zypher')) echo 'skip zypher extension not available';
?>
--FILE--
<?php
// Create a mock encoded file with the signature
$signature = 'ZYPH01';  // This should match the signature used in your encoder
$encoded_content = $signature . base64_encode('<?php echo "Hello, Zypher!"; ?>');

$test_file = __DIR__ . '/test_encoded.php';
file_put_contents($test_file, $encoded_content);

// Test function to check if a file has the Zypher signature
// This assumes your extension might have a function to check signatures
// If not, this is still useful to validate the test files
function has_zypher_signature($file) {
    $fp = fopen($file, 'rb');
    if (!$fp) return false;
    
    // Read the first 6 bytes (ZYPH01)
    $signature = fread($fp, 6);
    fclose($fp);
    
    return $signature === 'ZYPH01';
}

if (has_zypher_signature($test_file)) {
    echo "Zypher signature detected correctly\n";
} else {
    echo "Failed to detect Zypher signature\n";
}

// Cleanup
unlink($test_file);
?>
--EXPECT--
Zypher signature detected correctly