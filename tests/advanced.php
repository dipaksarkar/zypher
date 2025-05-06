<?php
/**
 * Advanced test file for Zypher PHP encoder
 */
class TestClass {
    private $value;
    
    public function __construct($value) {
        $this->value = $value;
    }
    
    public function getValue() {
        return $this->value;
    }
    
    public function setValue($value) {
        $this->value = $value;
    }
}

function calculateSum($a, $b) {
    return $a + $b;
}

// Create an object
$obj = new TestClass("Zypher Test");
echo "Object value: " . $obj->getValue() . "\n";

// Test function
$sum = calculateSum(10, 32);
echo "10 + 32 = " . $sum . "\n";

// Show phpinfo summary
echo "PHP Version: " . phpversion() . "\n";
