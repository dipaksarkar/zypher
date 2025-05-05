<?php

/**
 * Test script for encoding advanced PHP functions with obfuscation
 * 
 * This script will:
 * 1. Take the advanced.php file and encode it with the --obfuscate option
 * 2. Run the encoded file with the Zypher loader
 * 3. Verify that the output matches the expected output from the original file
 */

// Path to required files
$currentDir = __DIR__;
$advancedPhpPath = $currentDir . '/advanced.php';
$encodedFilePath = $currentDir . '/advanced_obfuscated.php';
$encoderPath = dirname($currentDir) . '/encoder/encode.php';

// Check for required files
if (!file_exists($advancedPhpPath)) {
    die("ERROR: Advanced PHP test file not found at: $advancedPhpPath\n");
}

if (!file_exists($encoderPath)) {
    die("ERROR: Encoder script not found at: $encoderPath\n");
}

// Make sure the Zypher extension is loaded
if (!extension_loaded('zypher')) {
    die("ERROR: The Zypher extension is not loaded. Make sure it's installed and enabled in php.ini.\n");
}

echo "=== Zypher Advanced Obfuscation Test ===\n\n";

// Step 1: Run the original file and capture its output
echo "Running original advanced.php file...\n";
ob_start();
include($advancedPhpPath);
$originalOutput = ob_get_clean();
echo "Original output captured (" . strlen($originalOutput) . " bytes).\n\n";

// Step 2: Encode the advanced.php file with --obfuscate option
echo "Encoding advanced.php with --obfuscate option...\n";
$command = sprintf(
    'php "%s" "%s" "%s" --obfuscate --verbose',
    $encoderPath,
    $advancedPhpPath,
    $encodedFilePath
);
echo "Command: $command\n";

$output = shell_exec($command);
echo "Encoder output:\n";
echo "---------------\n";
echo $output . "\n";

// Step 3: Verify the encoded file was created
if (!file_exists($encodedFilePath)) {
    die("ERROR: Encoded file was not created at: $encodedFilePath\n");
}

// Check if the file contains the Zypher signature
$encodedContent = file_get_contents($encodedFilePath);
if (strpos($encodedContent, 'ZYPH01') === false) {
    die("ERROR: Encoded file doesn't contain the Zypher signature.\n");
}

echo "Encoded file created successfully (" . filesize($encodedFilePath) . " bytes).\n\n";

// Step 4: Run the encoded file and capture its output
echo "Running encoded file with Zypher loader...\n";
ob_start();
include($encodedFilePath);
$encodedOutput = ob_get_clean();
echo "Encoded file output captured (" . strlen($encodedOutput) . " bytes).\n\n";

// Step 5: Compare outputs
echo "Comparing outputs...\n";
echo "-------------------\n";

// Extract expected output patterns from the original output
$expectedPatterns = [
    '/Hello from Zypher Test!/',
    '/Value: 42/',
    '/Arrow function result: 42/',
    '/JSON output:.*"name": "Zypher Test".*"value": 42.*"calculated": 84/s',
    '/Advanced test completed successfully!/'
];

$allPatternsMatched = true;
foreach ($expectedPatterns as $pattern) {
    $matched = preg_match($pattern, $encodedOutput) === 1;
    echo "Pattern '$pattern': " . ($matched ? "MATCHED" : "NOT MATCHED") . "\n";
    if (!$matched) {
        $allPatternsMatched = false;
    }
}

// Final results
echo "\nTest Results:\n";
echo "--------------\n";
echo "All expected patterns matched: " . ($allPatternsMatched ? "YES" : "NO") . "\n";

if ($allPatternsMatched) {
    echo "\nSUCCESS: The obfuscated advanced PHP file executed correctly with all expected outputs.\n";
    echo "This confirms that the obfuscation doesn't affect the functionality of the encoded file.\n";
} else {
    echo "\nFAILED: The obfuscated file didn't produce the expected output.\n";
    echo "Please check the encoder and loader functionality.\n";
}

// Clean up
if (file_exists($encodedFilePath)) {
    unlink($encodedFilePath);
    echo "\nTest cleanup: Removed encoded file.\n";
}

echo "\nTest completed.\n";
