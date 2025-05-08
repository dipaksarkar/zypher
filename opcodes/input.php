<?php

/**
 * Zypher Advanced Test File
 * This file demonstrates more complex PHP features that should be properly encoded and decoded
 */

namespace Zypher\Test;

class AdvancedTest
{
    private string $secret;
    private array $data;
    protected static int $counter = 0;

    public function __construct(string $secret = "This is a secret value")
    {
        $this->secret = $secret;
        $this->data = [
            'timestamp' => time(),
            'random' => bin2hex(random_bytes(16)),
            'info' => [
                'php_version' => PHP_VERSION,
                'encrypted' => true,
                'created' => date('Y-m-d H:i:s')
            ]
        ];
        self::$counter++;
    }

    public function getSecret(): string
    {
        return $this->secret;
    }

    public function getData(): array
    {
        return $this->data;
    }

    public static function getCounter(): int
    {
        return self::$counter;
    }

    /**
     * Test method with complex logic and variable types
     */
    public function processData(int $modifier = 1): array
    {
        $result = [];

        // Test array manipulation
        foreach ($this->data as $key => $value) {
            if (is_array($value)) {
                $result[$key] = array_map(function ($item) use ($modifier) {
                    return is_string($item) ? $item . " (modified x{$modifier})" : $item;
                }, $value);
            } else if (is_numeric($value)) {
                $result[$key] = $value * $modifier;
            } else {
                $result[$key] = $value;
            }
        }

        // Add some computed values
        $result['computed'] = [
            'hash' => hash('sha256', $this->secret),
            'instance_id' => spl_object_id($this),
            'memory_usage' => memory_get_usage(true)
        ];

        return $result;
    }
}

// Execute some code to test the encoding/decoding
$test = new AdvancedTest();
echo "=== Zypher Advanced Test ===\n";
echo "Secret: " . $test->getSecret() . "\n";
echo "Timestamp: " . $test->getData()['timestamp'] . "\n";
echo "Random ID: " . $test->getData()['random'] . "\n";
echo "PHP Version: " . $test->getData()['info']['php_version'] . "\n";
echo "Created: " . $test->getData()['info']['created'] . "\n";
echo "\nProcessed Data Sample:\n";
print_r($test->processData(2));
echo "\nInstance Count: " . AdvancedTest::getCounter() . "\n";
echo "=== Test Complete ===\n";
