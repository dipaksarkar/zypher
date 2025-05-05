<?php

/**
 * Complex code structure test
 * Tests complex nesting, callbacks, and advanced control structures
 * Ideal for testing obfuscation and statement shuffling
 */

// Complex nested class structure
class DataProcessor
{
    private $data = [];
    private $processors = [];
    private $debugMode = false;

    public function __construct(array $initialData = [])
    {
        $this->data = $initialData;
        $this->setupDefaultProcessors();
    }

    private function setupDefaultProcessors()
    {
        // Setup some default processors using closures
        $this->addProcessor('uppercase', function ($value) {
            return is_string($value) ? strtoupper($value) : $value;
        });

        $this->addProcessor('lowercase', function ($value) {
            return is_string($value) ? strtolower($value) : $value;
        });

        $this->addProcessor('double', function ($value) {
            return is_numeric($value) ? $value * 2 : $value;
        });
    }

    public function addProcessor($name, callable $callback)
    {
        $this->processors[$name] = $callback;
        if ($this->debugMode) {
            echo "Added processor: $name\n";
        }
        return $this;
    }

    public function add($key, $value)
    {
        $this->data[$key] = $value;
        return $this;
    }

    public function process($processorName = null)
    {
        $result = [];

        if ($processorName !== null) {
            // Use specific processor if it exists
            if (!isset($this->processors[$processorName])) {
                throw new RuntimeException("Processor '$processorName' not found");
            }

            $processor = $this->processors[$processorName];
            foreach ($this->data as $key => $value) {
                $result[$key] = $processor($value);
            }
        } else {
            // Complex nested loops and conditionals
            foreach ($this->data as $key => $value) {
                // Apply different processors based on data type
                if (is_string($value)) {
                    if (strlen($value) > 10) {
                        $result[$key] = call_user_func($this->processors['uppercase'], $value);
                    } else {
                        $result[$key] = call_user_func($this->processors['lowercase'], $value);
                    }
                } else if (is_numeric($value)) {
                    if ($value > 100) {
                        // Complex condition
                        $result[$key] = $value;
                    } else if ($value < 0) {
                        $result[$key] = abs($value);
                    } else {
                        $result[$key] = call_user_func($this->processors['double'], $value);
                    }
                } else if (is_array($value)) {
                    $subResult = [];
                    foreach ($value as $subKey => $subValue) {
                        $subResult[$subKey] = is_string($subValue)
                            ? call_user_func($this->processors['uppercase'], $subValue)
                            : $subValue;
                    }
                    $result[$key] = $subResult;
                } else {
                    $result[$key] = $value;
                }
            }
        }

        return $result;
    }

    public function setDebugMode($mode)
    {
        $this->debugMode = (bool)$mode;
        return $this;
    }

    public function getData()
    {
        return $this->data;
    }
}

// Complex recursive function
function fibonacci($n, &$memo = [])
{
    if ($n <= 1) {
        return $n;
    }

    if (!isset($memo[$n])) {
        $memo[$n] = fibonacci($n - 1, $memo) + fibonacci($n - 2, $memo);
    }

    return $memo[$n];
}

// Generate Fibonacci sequence
$fibSequence = [];
for ($i = 0; $i < 10; $i++) {
    $fibSequence[] = fibonacci($i);
}

// Multiple nested conditionals
function categorizeValue($value)
{
    if (is_numeric($value)) {
        if ($value > 0) {
            if ($value > 100) {
                if ($value > 1000) {
                    return "very large number";
                } else {
                    return "large number";
                }
            } else {
                if ($value < 10) {
                    return "small number";
                } else {
                    return "medium number";
                }
            }
        } else if ($value < 0) {
            return "negative number";
        } else {
            return "zero";
        }
    } else if (is_string($value)) {
        if (strlen($value) == 0) {
            return "empty string";
        } else if (is_numeric($value)) {
            return "numeric string";
        } else if (ctype_alpha($value)) {
            return "alphabetic string";
        } else {
            return "mixed string";
        }
    } else if (is_bool($value)) {
        return $value ? "true" : "false";
    } else if (is_array($value)) {
        return count($value) == 0 ? "empty array" : "non-empty array";
    } else if (is_object($value)) {
        return "object of class " . get_class($value);
    } else {
        return "unknown type";
    }
}

// Test data
$testValues = [
    'name' => 'Alice',
    'COMPANY' => 'Acme Corp',
    'age' => 30,
    'balance' => 1500,
    'negative' => -50,
    'tags' => ['php', 'coding', 'TEST'],
    'longText' => 'This is a really long text that should be converted to uppercase'
];

// Test the complex class
$processor = new DataProcessor($testValues);
$processor->setDebugMode(true);

// Add a custom processor with complex logic
$processor->addProcessor('conditional', function ($value) use ($fibSequence) {
    if (is_numeric($value)) {
        if (in_array($value, $fibSequence)) {
            return "Fibonacci: $value";
        } else {
            return $value % 2 == 0 ? "Even: $value" : "Odd: $value";
        }
    } else if (is_string($value)) {
        return ucwords(strtolower($value));
    } else {
        return $value;
    }
});

// Process the data
$upperResult = $processor->process('uppercase');
$lowerResult = $processor->process('lowercase');
$customResult = $processor->process('conditional');
$defaultResult = $processor->process();

// Use the categorize function
$categories = [];
foreach ($testValues as $key => $value) {
    $categories[$key] = categorizeValue($value);
}
$categories['processor'] = categorizeValue($processor);
$categories['fibonacci'] = categorizeValue($fibSequence);

echo "Default processing results:\n";
print_r($defaultResult);

echo "Categories:\n";
print_r($categories);

echo "Fibonacci sequence: " . implode(", ", $fibSequence) . "\n";

// Return results for testing
return [
    'status' => 'success',
    'message' => 'Complex code test completed',
    'results' => [
        'upper' => $upperResult,
        'lower' => $lowerResult,
        'custom' => $customResult,
        'default' => $defaultResult,
        'categories' => $categories
    ]
];
