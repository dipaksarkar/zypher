--TEST--
Test stub code implementation when extension isn't loaded
--SKIPIF--
<?php
// This test requires the extension to be available to encode the file
// but will check what happens when it's not loaded
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
$test_file = __DIR__ . '/test_stub_script.php';
file_put_contents($test_file, '<?php echo "This should not be executed if extension is not loaded"; ?>');

// Path to the encoder 
$encoder_path = dirname(dirname(__DIR__)) . '/encoder/encode.php';
$encoded_file = __DIR__ . '/test_stub_script_encoded.php';

// Encode the file
$cmd = "php $encoder_path $test_file $encoded_file";
passthru($cmd, $return_var);

// Verify the file was encoded correctly
if (!file_exists($encoded_file)) {
    die("Failed to create encoded file");
}

// Create a PHP script that will load the encoded file with the extension disabled
$test_runner_file = __DIR__ . '/test_stub_runner.php';
file_put_contents($test_runner_file, '<?php 
// Simulate that the extension is not loaded
function extension_loaded($name) { 
    if ($name == "zypher") {
        return false;
    }
    return \extension_loaded($name);
}

// Include the encoded file - should trigger the error stub
ob_start();
include "' . $encoded_file . '";
$output = ob_get_clean();

// Check if the output contains the expected error message
if (strpos($output, "the Zypher Loader for PHP needs to be installed") !== false) {
    echo "Stub code working correctly\n";
} else {
    echo "Error: Stub code not working!\n";
    echo "Output was: " . $output . "\n";
}
?>');

// Run the test runner
passthru("php $test_runner_file");

// Clean up
@unlink($test_file);
@unlink($encoded_file);
@unlink($test_runner_file);

echo "Done\n";
?>
--EXPECT--
Stub code working correctly
Done