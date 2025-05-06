<?php

/**
 * Zypher Basic Test File
 * This file tests the basic functionality of the Zypher encoder/decoder system
 */

class ZypherBasicTest
{
    private $message;
    private $creationTime;

    public function __construct($message = "Hello from Zypher!")
    {
        $this->message = $message;
        $this->creationTime = time();
    }

    public function getMessage()
    {
        return $this->message;
    }

    public function getCreationTime($format = 'Y-m-d H:i:s')
    {
        return date($format, $this->creationTime);
    }

    public function setMessage($message)
    {
        $this->message = $message;
        return $this;
    }

    public function generateHash()
    {
        return md5($this->message . $this->creationTime);
    }
}

// Create an instance of our test class
$test = new ZypherBasicTest();

// Display basic information 
echo "=== Zypher Basic Test ===\n";
echo "PHP Version: " . PHP_VERSION . "\n";
echo "Current Time: " . date('Y-m-d H:i:s') . "\n";
echo "Message: " . $test->getMessage() . "\n";
echo "Creation Time: " . $test->getCreationTime() . "\n";
echo "Hash: " . $test->generateHash() . "\n";

// Modify and test again
$test->setMessage("Modified message - still works!");
echo "\nAfter modification:\n";
echo "Message: " . $test->getMessage() . "\n";
echo "Hash: " . $test->generateHash() . "\n";

// Test some PHP functions to ensure they work properly after encoding
echo "\nSystem Information:\n";
echo "Server: " . php_uname() . "\n";
echo "SAPI: " . php_sapi_name() . "\n";
echo "Memory: " . round(memory_get_usage() / 1024 / 1024, 2) . " MB\n";

// Test file is encoded correctly
if (function_exists('zypher_decode_string')) {
    echo "\nZypher extension is loaded - decoding functions available.\n";
} else {
    echo "\nRunning in standard PHP mode (no Zypher extension detected).\n";
}

echo "=== Test Complete ===\n";
