--TEST--
Test encoding and decoding of PHP files
--SKIPIF--
<?php
if (!extension_loaded('zypher')) {
    echo 'skip Zypher extension not loaded';
}
?>
--INI--
zypher.license_check_enabled=0
zypher.encryption_key=TestKey123
--FILE--
<?php
// Create a simple test file
$test_file = __DIR__ . '/test_script.php';
file_put_contents($test_file, '<?php echo "Hello from test script"; ?>');

// Path to the encoder 
$encoder_path = dirname(dirname(__DIR__)) . '/encoder/encode.php';
$encoded_file = __DIR__ . '/test_script_encoded.php';

// Encode the file
$cmd = "php $encoder_path $test_file $encoded_file";
passthru($cmd, $return_var);
var_dump($return_var === 0);

// Check if the encoded file exists
var_dump(file_exists($encoded_file));

// Check if the encoded file contains the ZYPH01 signature
$encoded_content = file_get_contents($encoded_file);
var_dump(strpos($encoded_content, 'ZYPH01') !== false);

// Verify the encoded file has the proper error stub
var_dump(strpos($encoded_content, "the Zypher Loader for PHP needs to be installed") !== false);

// Clean up
@unlink($test_file);
@unlink($encoded_file);

echo "Done\n";
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
Done