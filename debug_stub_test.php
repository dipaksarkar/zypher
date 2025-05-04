<?php
// Create a simple test file
$test_file = "/tmp/test_stub_script.php";
file_put_contents($test_file, "<?php echo \"This should not be executed if extension is not loaded\"; ?>");

// Path to the encoder 
$encoder_path = __DIR__ . "/encoder/encode.php";
$encoded_file = "/tmp/test_stub_script_encoded.php";

// Encode the file - using quiet mode
$cmd = "php $encoder_path $test_file $encoded_file --quiet";
$output = shell_exec($cmd);
echo "Encoding completed
";

// Verify the file was encoded correctly
if (!file_exists($encoded_file)) {
    die("Failed to create encoded file");
}

// Get encoded content
$encoded_content = file_get_contents($encoded_file);
echo "File size: " . strlen($encoded_content) . " bytes
";

// Check if the encoded file contains the error message
if (strpos($encoded_content, "Zypher Loader for PHP needs to be installed") !== false) {
    echo "SUCCESS: Stub code is correctly included in the encoded file
";
} else {
    echo "FAILURE: Stub code is missing in the encoded file
";
    // Print the beginning of the file
    echo "First 200 bytes of the file:
";
    echo substr(bin2hex($encoded_content), 0, 200) . "
";
}

// Clean up
@unlink($test_file);
@unlink($encoded_file);

echo "Done
";
?>
