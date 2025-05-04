<?php

/**
 * Simple test file for Zypher PHP encoder/loader system
 */

echo "Simple Test - Zypher PHP Encoder/Loader\n";
echo "======================================\n\n";

// Display some information to verify execution
echo "Current time: " . date('Y-m-d H:i:s') . "\n";
echo "PHP Version: " . PHP_VERSION . "\n";

// Perform a simple calculation
$result = 0;
for ($i = 1; $i <= 5; $i++) {
    $result += $i * 2;
}
echo "Calculation result: $result\n\n";

// Create a simple array and display it
$fruits = ['apple', 'banana', 'orange', 'grape', 'kiwi'];
echo "Fruits array:\n";
foreach ($fruits as $index => $fruit) {
    echo " - Item $index: $fruit\n";
}

echo "\nIf you can see this message, the Zypher encoding/decoding system is working correctly!\n";
