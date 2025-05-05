--TEST--
Zypher obfuscation support with advanced PHP features
--SKIPIF--
<?php
if (!extension_loaded('zypher')) die('skip: zypher extension not available');
?>
--FILE--
<?php
/**
 * Test file for the Zypher obfuscation support
 * This test verifies that the obfuscation feature works correctly with advanced PHP features
 * such as namespaces, traits, anonymous functions, type declarations, etc.
 */

// Path to encoder
$encoderPath = dirname(__DIR__) . '/../encoder/encode.php';
if (!file_exists($encoderPath)) {
    die("Encoder not found at: $encoderPath\n");
}

// Create temporary files for the test
$testDir = sys_get_temp_dir() . '/zypher_test_' . uniqid();
if (!file_exists($testDir)) {
    mkdir($testDir, 0777, true);
}
$testFile = $testDir . '/advanced_obfuscation_test.php';
$encodedFile = $testDir . '/advanced_obfuscation_test_encoded.php';

echo "Zypher Advanced Obfuscation Test\n";
echo "==============================\n\n";

// Create a test file with advanced PHP features that should be obfuscated
file_put_contents($testFile, '<?php
// Advanced PHP features test file for obfuscation

namespace ZypherTest\Encoding {
    
    /**
     * Demonstration trait with typed properties
     */
    trait LoggableTrait {
        protected string $logPrefix = "ZYPHER";
        
        public function log(string $message): void {
            echo "{$this->logPrefix}: $message\n";
        }
        
        public function setLogPrefix(string $prefix): void {
            $this->logPrefix = $prefix;
        }
    }
    
    /**
     * Interface for encodable objects
     */
    interface Encodable {
        public function encode(): string;
        public function decode(string $data): self;
    }
    
    /**
     * Example class using modern PHP features
     */
    class AdvancedFeatures implements Encodable {
        use LoggableTrait;
        
        // Typed properties
        private string $secret;
        protected array $data = [];
        public int $counter = 0;
        
        // Constructor property promotion
        public function __construct(
            private string $name,
            private ?int $value = null,
            private readonly bool $isActive = true
        ) {
            $this->secret = "Secret" . mt_rand(1000, 9999);
            $this->setLogPrefix($name);
        }
        
        // Return type declarations
        public function getName(): string {
            return $this->name;
        }
        
        // Nullable return types
        public function getValue(): ?int {
            return $this->value;
        }
        
        // Union types (PHP 8.0+)
        public function processData(array|object $input): array {
            if (is_object($input)) {
                $input = (array)$input;
            }
            
            $this->data = array_merge($this->data, $input);
            $this->counter++;
            
            // Array unpacking with named keys
            return [
                "processed" => true,
                "timestamp" => time(),
                ...$this->data
            ];
        }
        
        // Implementation of interface methods
        public function encode(): string {
            return base64_encode(json_encode([
                "name" => $this->name,
                "value" => $this->value,
                "active" => $this->isActive,
                "counter" => $this->counter,
                "data" => $this->data,
                "secret" => $this->secret
            ]));
        }
        
        public function decode(string $data): self {
            $decoded = json_decode(base64_decode($data), true);
            
            $this->name = $decoded["name"];
            $this->value = $decoded["value"];
            $this->counter = $decoded["counter"];
            $this->data = $decoded["data"];
            $this->secret = $decoded["secret"];
            
            return $this;
        }
    }
}

namespace ZypherTest\Demo {
    // Importing from another namespace
    use ZypherTest\Encoding\AdvancedFeatures;
    
    // Match expression (PHP 8.0+)
    function determineType($value): string {
        return match(gettype($value)) {
            "string" => "Text: $value",
            "integer", "double" => "Number: $value",
            "array" => "Collection with " . count($value) . " items",
            "object" => "Instance of " . get_class($value),
            default => "Unknown type"
        };
    }
    
    // Variadic functions with named arguments
    function formatItems(string $prefix, string $separator = ", ", array $items = []): string {
        return $prefix . implode($separator, $items);
    }
    
    // Using an anonymous class
    $factory = new class {
        public function create(string $name, ?int $value): AdvancedFeatures {
            return new AdvancedFeatures($name, $value);
        }
    };
    
    // Create and use the test object
    $testObject = $factory->create("TestObject", 42);
    $testObject->log("Object created with value " . $testObject->getValue());
    
    // Process some data with the object
    $result = $testObject->processData(["key1" => "value1", "key2" => "value2"]);
    $testObject->log("Data processed: " . json_encode($result));
    
    // Using arrow functions (PHP 7.4+)
    $double = fn($x) => $x * 2;
    echo "Double of 21: " . $double(21) . "\n";
    
    // Using anonymous function with use statement
    $multiplier = 3;
    $triple = function($x) use ($multiplier) {
        return $x * $multiplier;
    };
    echo "Triple of 14: " . $triple(14) . "\n";
    
    // Output object details using the determineType function
    echo "Object type: " . determineType($testObject) . "\n";
    
    // Test variadic function with named arguments - FIX: passing array as explicit argument
    echo formatItems(
        prefix: "Items: ",
        separator: " | ",
        items: ["apple", "banana", "cherry"]
    ) . "\n";
    
    // Test encoding and decoding
    $encoded = $testObject->encode();
    echo "Encoded data: " . substr($encoded, 0, 30) . "...\n";
    
    $newObject = $factory->create("NewObject", 100);
    $newObject->decode($encoded);
    echo "Decoded object name: " . $newObject->getName() . "\n";
    echo "Decoded object value: " . $newObject->getValue() . "\n";
    
    echo "TEST COMPLETED SUCCESSFULLY\n";
}
?>');

// Execute the encoder with the --obfuscate option
$command = sprintf(
    'php "%s" "%s" "%s" --obfuscate --verbose 2>&1',
    $encoderPath,
    $testFile,
    $encodedFile
);

echo "Running encoder: " . $command . "\n";
$output = shell_exec($command);

echo "Encoder output:\n";
echo "---------------\n";
echo substr($output, 0, 500) . (strlen($output) > 500 ? "...[truncated]" : "") . "\n\n";

// Check if the encoded file was created
if (!file_exists($encodedFile)) {
    echo "FAILED: Encoded file was not created\n";
    exit(1);
}

// Check if the file contains obfuscated variables
$encodedContent = file_get_contents($encodedFile);

$originalTokens = [
    '$logPrefix',     // Trait property
    '$message',       // Trait method parameter
    '$prefix',        // Trait method parameter
    '$secret',        // Class property
    '$data',          // Class property
    '$counter',       // Class property
    '$name',          // Constructor promoted property
    '$value',         // Constructor promoted property
    '$isActive',      // Constructor promoted property
    '$input',         // Method parameter
    '$decoded',       // Local variable
    '$testObject',    // Global variable
    '$factory',       // Global variable
    '$double',        // Arrow function
    '$multiplier',    // Used in anonymous function
    '$triple',        // Anonymous function
    '$encoded',       // Global variable
    '$newObject'      // Global variable
];

$obfuscationSuccess = true;
$foundOriginalVariables = [];

foreach ($originalTokens as $varName) {
    if (strpos($encodedContent, $varName) !== false) {
        $obfuscationSuccess = false;
        $foundOriginalVariables[] = $varName;
    }
}

// Check advanced PHP features in output
$containsObfuscatedContent = 
    strpos($output, 'code obfuscation') !== false || 
    strpos($output, 'obfuscation techniques') !== false;

echo "Results:\n";
echo "--------\n";
echo "Encoded file created: " . (file_exists($encodedFile) ? "YES" : "NO") . "\n";
if (!empty($foundOriginalVariables)) {
    echo "WARNING: Found " . count($foundOriginalVariables) . " original variable names in encoded file:\n";
    echo "  " . implode(', ', $foundOriginalVariables) . "\n";
} else {
    echo "All tested variable names successfully obfuscated.\n";
}
echo "Evidence of obfuscation in output: " . ($containsObfuscatedContent ? "YES" : "NO") . "\n\n";

// Now run the original file to get baseline output
echo "Running original test file...\n";
echo "-------------------------\n";
$origOutput = shell_exec("php $testFile");
echo $origOutput . "\n";

// Now clean up the test files
@unlink($testFile);
@unlink($encodedFile);
@rmdir($testDir);

echo "Test completed.\n";
?>
--EXPECTF--
Zypher Advanced Obfuscation Test
==============================

Running encoder: php "%s" "%s" "%s" --obfuscate --verbose %s
Encoder output:
---------------
=== Zypher PHP Encoder ===
Source: %s
Destination: %s
Processing file...
DEBUG: Generated random file key: %s (length: 32)
DEBUG: %s
DEBUG: Using master key: %s
Applying code obfuscation techniques to %s%s

Results:
--------
Encoded file created: YES
All tested variable names successfully obfuscated.
Evidence of obfuscation in output: YES

Running original test file...
-------------------------
TestObject: Object created with value 42
TestObject: Data processed: {"processed":true,"timestamp":%d,"key1":"value1","key2":"value2"}
Double of 21: 42
Triple of 14: 42
Object type: Instance of ZypherTest\Encoding\AdvancedFeatures
Items: apple | banana | cherry
Encoded data: eyJuYW1lIjoiVGVzdE9iamVjdCIsIn...
Decoded object name: TestObject
Decoded object value: 42
TEST COMPLETED SUCCESSFULLY

Test completed.