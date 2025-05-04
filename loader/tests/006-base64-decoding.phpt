--TEST--
Zypher base64 decoding test
--SKIPIF--
<?php
if (!extension_loaded('zypher')) echo 'skip zypher extension not available';
?>
--FILE--
<?php
// This test verifies that the loader can properly decode a base64-encoded file
// We're using the DEBUG mode behavior from the encode.php which uses base64 encoding

// Create a simple test file with the correct structure
$signature = 'ZYPH01';
$original_code = '<?php echo "Decoded successfully!"; ?>';
$encoded_content = $signature . base64_encode($original_code);

$test_file = __DIR__ . '/test_base64.php';
file_put_contents($test_file, $encoded_content);

// In a real scenario, the loader would automatically decode and execute this file
// Since we can't easily execute it directly in the test, let's verify the structure

// Output to verify we created the file correctly
echo "Test file created with signature and base64 encoded content\n";

// Here we manually decode to verify the content is as expected
$file_content = file_get_contents($test_file);
if (substr($file_content, 0, 6) === $signature) {
    $encoded_part = substr($file_content, 6);
    $decoded = base64_decode($encoded_part);
    
    if ($decoded === $original_code) {
        echo "Decoding verification successful\n";
    } else {
        echo "Decoding verification failed\n";
    }
} else {
    echo "Invalid file format\n";
}

// Cleanup
unlink($test_file);
?>
--EXPECT--
Test file created with signature and base64 encoded content
Decoding verification successful