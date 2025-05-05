<?php

/**
 * Basic PHP functionality test file
 * Tests variables, loops, conditionals, and functions
 */

// Constants and variables
define('TEST_CONSTANT', 'This is a test constant');
$globalVar = "I am a global variable";

// Basic function declaration
function basicTest($param1, $param2 = 'default')
{
    $localVar = "I am a local variable";
    $result = $localVar . " with params: " . $param1 . ", " . $param2;
    return $result;
}

// Arrays
$simpleArray = ['apple', 'banana', 'cherry'];
$assocArray = [
    'name' => 'Test User',
    'email' => 'test@example.com',
    'age' => 30
];

// Control structures
if (count($simpleArray) > 0) {
    echo "Array has " . count($simpleArray) . " items\n";
}

// Loops
echo "Looping through array:\n";
foreach ($simpleArray as $key => $value) {
    echo "$key: $value\n";
}

// While loop
$i = 0;
while ($i < 3) {
    echo "While loop iteration: $i\n";
    $i++;
}

// For loop
for ($j = 0; $j < 3; $j++) {
    echo "For loop iteration: $j\n";
}

// Switch statement
$fruit = 'apple';
switch ($fruit) {
    case 'apple':
        echo "Selected fruit is an apple\n";
        break;
    case 'banana':
        echo "Selected fruit is a banana\n";
        break;
    default:
        echo "Unknown fruit\n";
        break;
}

// Try-catch block
try {
    throw new Exception("Test exception");
} catch (Exception $e) {
    echo "Caught exception: " . $e->getMessage() . "\n";
} finally {
    echo "Finally block executed\n";
}

// Function usage
echo basicTest("Hello", "World") . "\n";

// Magic constants
echo "Current file: " . __FILE__ . "\n";
echo "Current line: " . __LINE__ . "\n";

// Return a result for testing
return [
    'status' => 'success',
    'message' => 'Basic PHP functionality test completed'
];
