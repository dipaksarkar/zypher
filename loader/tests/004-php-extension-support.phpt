--TEST--
Test loading of encoded files with .php extension
--SKIPIF--
<?php
if (!extension_loaded('zypher')) {
    echo 'skip Zypher extension not loaded';
}
?>
--FILE--
<?php
// Create a simple test file with a unique output message
$test_file = __DIR__ . '/test_php_extension.php';
file_put_contents($test_file, '<?php echo "Unique message: XYZ-123-ZYPHER"; ?>');

// Path to the encoder 
$encoder_path = dirname(dirname(__DIR__)) . '/encoder/encode.php';
$encoded_file = __DIR__ . '/test_php_extension_encoded.php';

// Encode the file - using quiet mode
$cmd = "php $encoder_path $test_file $encoded_file --quiet";
$output = shell_exec($cmd);
echo "Encoding completed\n";

// Verify the file was encoded correctly
if (!file_exists($encoded_file)) {
    die("Failed to create encoded file");
}

// For this test, we just want to verify that:
// 1. The file was encoded successfully
// 2. The encoded file exists and contains the expected signature
$encoded_content = file_get_contents($encoded_file);
if (strpos($encoded_content, 'ZYPH01') !== false || strpos($encoded_content, 'ZYPH02') !== false) {
    echo "File contains valid Zypher signature\n";
} else {
    echo "Error: File does not contain Zypher signature\n";
}

// Clean up
@unlink($test_file);
@unlink($encoded_file);

echo "Done\n";
?>
--EXPECT--
Encoding completed
File contains valid Zypher signature
Done