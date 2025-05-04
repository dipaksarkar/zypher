<?php

/**
 * Advanced test file for Zypher encoding
 * 
 * This file tests more complex PHP features to ensure they're properly
 * encoded and decoded by the Zypher loader.
 */

namespace ZypherTest;

class TestClass
{
    private $name;
    private $value;

    public function __construct(string $name, $value = null)
    {
        $this->name = $name;
        $this->value = $value;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getValue()
    {
        return $this->value;
    }

    public function sayHello(): void
    {
        echo "Hello from {$this->name}!\n";
    }
}

// Create a test instance
$test = new TestClass("Zypher Test", 42);
$test->sayHello();
echo "Value: " . $test->getValue() . "\n";

// Test some PHP 7+ features
$arrowFunction = fn($x) => $x * 2;
echo "Arrow function result: " . $arrowFunction(21) . "\n";

// Test array handling
$array = [
    'name' => $test->getName(),
    'value' => $test->getValue(),
    'calculated' => $arrowFunction($test->getValue())
];

echo "JSON output: " . json_encode($array, JSON_PRETTY_PRINT) . "\n";

// Output successful test completion
echo "Advanced test completed successfully!\n";
