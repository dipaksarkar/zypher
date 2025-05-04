<?php
/**
 * Advanced test file for Zypher encoder/loader
 * This tests more complex PHP functionality
 */

class ZypherTest {
    private $name;
    private $encryptionType;
    
    public function __construct(string $name, string $encryptionType = 'AES-256-CBC') {
        $this->name = $name;
        $this->encryptionType = $encryptionType;
    }
    
    public function getName(): string {
        return $this->name;
    }
    
    public function getEncryptionDetails(): array {
        return [
            'name' => $this->name,
            'encryption' => $this->encryptionType,
            'strength' => '256-bit',
            'php_version' => PHP_VERSION,
            'time' => date('Y-m-d H:i:s')
        ];
    }
    
    public function printDetails(): void {
        $details = $this->getEncryptionDetails();
        echo "=== Zypher Test Details ===\n";
        foreach ($details as $key => $value) {
            echo "$key: $value\n";
        }
        echo "=========================\n";
    }
}

// Create an instance and display details
$test = new ZypherTest('Enhanced Zypher System');
$test->printDetails();

// Test some PHP 8.3+ features
$numbers = [1, 2, 3, 4, 5];
$doubled = array_map(fn($n) => $n * 2, $numbers);
echo "Doubled numbers: " . implode(', ', $doubled) . "\n";

// Demonstrate that this file was loaded through the Zypher system
echo "This PHP file was successfully loaded and executed through the Zypher encoder/loader system.\n";
echo "Current execution time: " . microtime(true) . "\n";