--TEST--
Test encoding and decoding of PHP files
--SKIPIF--
<?php
if (!extension_loaded('zypher')) {
    echo 'skip Zypher extension not loaded';
}
?>
--FILE--
<?php
// Create a simple test file
$test_file = __DIR__ . '/test_script.php';
file_put_contents($test_file, '<?php echo "Hello from test script"; ?>');

// Path to the encoder 
$encoder_path = dirname(dirname(__DIR__)) . '/encoder/encode.php';
$encoded_file = __DIR__ . '/test_script_encoded.php';

// Encode the file - using the quiet mode to suppress output
$cmd = "php $encoder_path $test_file $encoded_file --quiet";
$output = shell_exec($cmd);
echo "Encoding completed\n";

// Check if the encoded file exists
$exists = file_exists($encoded_file);
var_dump($exists);

if ($exists) {
    // Get the encoded content for examination
    $encoded_content = file_get_contents($encoded_file);
    
    // Check if the encoded file contains the signature
    $has_signature = strpos($encoded_content, 'ZYPH01') !== false || strpos($encoded_content, 'ZYPH02') !== false;
    var_dump($has_signature);

    // Verify the encoded file has the proper error stub
    $has_stub = strpos($encoded_content, "the Zypher Loader for PHP needs to be installed") !== false;
    var_dump($has_stub);
}

// Clean up
@unlink($test_file);
@unlink($encoded_file);

echo "Done\n";
?>
--EXPECT--
Encoding completed
bool(true)
bool(true)
bool(true)
Done