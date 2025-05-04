<?php

/**
 * Test script for Zypher encoder and loader
 * 
 * This script performs the following tests:
 * 1. Run original PHP files
 * 2. Encode them with Zypher
 * 3. Run encoded files to verify loader works
 */

// Directory setup
$testDir = __DIR__;
$encoderPath = realpath($testDir . '/../encoder/encode.php');
$extension = extension_loaded('zypher') ? 'Loaded' : 'Not loaded';

echo "==========================================\n";
echo "Zypher Testing Framework\n";
echo "==========================================\n";
echo "Zypher Extension: $extension\n";
echo "Encoder Path: $encoderPath\n";
echo "Test Directory: $testDir\n";
echo "==========================================\n\n";

// List of files to test
$testFiles = [
    'hello.php',
    'advanced.php'
];

// Run tests for each file
foreach ($testFiles as $file) {
    $filePath = $testDir . '/' . $file;
    $encodedFilePath = $testDir . '/' . pathinfo($file, PATHINFO_FILENAME) . '_encoded.php';

    echo "Testing file: $file\n";
    echo "----------------------------------------\n";

    // Test 1: Run original file
    echo "ORIGINAL OUTPUT:\n";
    echo "----------------------------------------\n";
    passthru("php \"$filePath\"");
    echo "\n----------------------------------------\n";

    // Test 2: Encode the file
    echo "Encoding file...\n";
    passthru("php \"$encoderPath\" \"$filePath\" \"$encodedFilePath\"");

    if (!file_exists($encodedFilePath)) {
        echo "ERROR: Encoding failed. Encoded file not found.\n";
        continue;
    }

    // Test 3: Check the structure of encoded file
    $encodedContent = file_get_contents($encodedFilePath);
    if (strpos($encodedContent, '<?php') !== 0) {
        echo "WARNING: Encoded file does not start with PHP tag\n";
    }

    if (strpos($encodedContent, 'ZYPH') === false) {
        echo "WARNING: Encoded file does not contain Zypher signature\n";
    }

    echo "Encoded file created: " . filesize($encodedFilePath) . " bytes\n";

    // Test 4: Run encoded file
    echo "----------------------------------------\n";
    echo "ENCODED FILE OUTPUT:\n";
    echo "----------------------------------------\n";
    passthru("php \"$encodedFilePath\"");
    echo "\n----------------------------------------\n\n";
}

echo "Tests completed.\n";
