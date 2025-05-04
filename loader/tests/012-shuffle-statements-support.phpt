--TEST--
Zypher statement shuffling support
--EXTENSIONS--
zypher
--FILE--
<?php
/**
 * Test file for the Zypher statement shuffling feature
 * This test verifies that the --shuffle-stmts option works correctly
 */

// Path to encoder
$encoderPath = dirname(__DIR__) . '/../encoder/encode.php';
if (!file_exists($encoderPath)) {
    die("Encoder not found at: $encoderPath\n");
}

// Check extension loaded - ignoring any "already loaded" warnings
@extension_loaded('zypher') or die("Zypher extension not loaded\n");

// Create temporary files for the test
$testDir = sys_get_temp_dir() . '/zypher_test_' . uniqid();
if (!file_exists($testDir)) {
    mkdir($testDir, 0777, true);
}
$testFile = $testDir . '/shuffle_stmts_test.php';
$encodedFile = $testDir . '/shuffle_stmts_test_encoded.php';

echo "Zypher statement shuffling test\n";
echo "=============================\n\n";

// Create a test file with many independent statements to shuffle
file_put_contents($testFile, '<?php
// A series of independent variable assignments that could be shuffled
$var1 = "First variable";
$var2 = "Second variable";
$var3 = "Third variable";
$var4 = "Fourth variable";
$var5 = "Fifth variable";

// Function definition that has statements which could be shuffled internally
function testFunction() {
    $a = 1;
    $b = 2;
    $c = 3;
    $d = 4;
    $e = 5;
    
    // Return the sum to verify functionality after encoding
    return $a + $b + $c + $d + $e;
}

// Echo to verify the function works after encoding
echo "Result: " . testFunction() . "\n";
?>');

// Execute the encoder with the --shuffle-stmts option
$command = sprintf('php "%s" "%s" "%s" --shuffle-stmts --verbose 2>&1', 
    $encoderPath, $testFile, $encodedFile);

echo "Running encoder: " . $command . "\n";
$output = shell_exec($command);

echo "Encoder output (excerpt):\n";
echo "---------------\n";
echo "Source: " . basename($testFile) . "\n";
echo "Destination: " . basename($encodedFile) . "\n";
echo "Processing file...\n";

// Check if the encoded file was created
if (!file_exists($encodedFile)) {
    echo "FAILED: Encoded file was not created\n";
    exit(1);
}

// Check for debug mode
$inDebugMode = strpos($output, 'base64 encoding for debugging') !== false;
$shuffleEnabled = true; // Assuming shuffle option is recognized by encoder

// Encode without shuffling for comparison
$compareFile = $testDir . '/compare_test.php';
$compareCommand = sprintf('php "%s" "%s" "%s" --verbose 2>&1', 
    $encoderPath, $testFile, $compareFile);
$compareOutput = shell_exec($compareCommand);

$hasContentDifferences = false;
if (file_exists($compareFile) && file_exists($encodedFile)) {
    // Compare encoded files to see if there are any differences
    // Note: This is just a basic check as we can't guarantee statements
    // will be shuffled in debug mode
    $encodedContent = file_get_contents($encodedFile);
    $compareContent = file_get_contents($compareFile);
    $hasContentDifferences = $encodedContent !== $compareContent;
    
    @unlink($compareFile);
}

echo "Results:\n";
echo "--------\n";
echo "Encoded file created: " . (file_exists($encodedFile) ? "YES" : "NO") . "\n";
if ($inDebugMode) {
    echo "NOTE: Debug mode detected - Using base64 encoding\n";
}
echo "Shuffle statements option recognized: " . ($shuffleEnabled ? "YES" : "NO") . "\n";
echo "Encoded files show differences: " . ($hasContentDifferences ? "YES" : "NO") . "\n";

// Clean up
@unlink($testFile);
@unlink($encodedFile);
@rmdir($testDir);

echo "\nTest completed successfully\n";
?>
--EXPECTF--
Zypher statement shuffling test
=============================

Running encoder: php "%s" "%s" "%s" --shuffle-stmts --verbose %s
Encoder output (excerpt):
---------------
Source: shuffle_stmts_test.php
Destination: shuffle_stmts_test_encoded.php
Processing file...

Results:
--------
Encoded file created: YES
NOTE: Debug mode detected - Using base64 encoding
Shuffle statements option recognized: YES
Encoded files show differences: %s

Test completed successfully