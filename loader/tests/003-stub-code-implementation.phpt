--TEST--
Test stub code implementation in encoded files
--SKIPIF--
<?php
if (!extension_loaded('zypher')) {
    echo 'skip Zypher extension not loaded';
}
?>
--FILE--
<?php
// Create a simple test file
$test_file = __DIR__ . '/test_stub_script.php';
file_put_contents($test_file, '<?php echo "This should not be executed if extension is not loaded"; ?>');

// Path to the encoder 
$encoder_path = dirname(dirname(__DIR__)) . '/bin/zypher';
$encoded_file = __DIR__ . '/test_stub_script_encoded.php';

// Encode the file - using quiet mode
$cmd = "php $encoder_path $test_file $encoded_file --quiet";
$output = shell_exec($cmd);
echo "Encoding completed\n";

// Verify the file was encoded correctly
if (!file_exists($encoded_file)) {
    die("Failed to create encoded file");
}

// Check if the encoded file contains proper stub code - look for multiple possible phrases
$encoded_content = file_get_contents($encoded_file);
$stub_detected = false;

// Check for various possible stub indicators
$stub_phrases = [
    'extension_loaded(\'zypher\')',
    'extension_loaded("zypher")',
    'corrupted',
    'PHP needs to be installed',
    'Loader'
];

foreach ($stub_phrases as $phrase) {
    if (strpos($encoded_content, $phrase) !== false) {
        $stub_detected = true;
        break;
    }
}

if ($stub_detected) {
    echo "Stub code is correctly included in the encoded file\n";
} else {
    echo "Error: Stub code is missing in the encoded file\n";
}

// Clean up
@unlink($test_file);
@unlink($encoded_file);

echo "Done\n";
?>
--EXPECT--
Encoding completed
Stub code is correctly included in the encoded file
Done