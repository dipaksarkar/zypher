<?php

/**
 * Comprehensive test file that tests ALL encoder features
 * This file combines all possible encoding and obfuscation techniques
 */

// Define a unique set of test cases for each encoder feature
class EncoderTestSuite
{
    // Class constants for testing
    const VERSION = '1.0.0';
    const SECRET_KEY = 'This is a secret key that should be encrypted';
    const MAX_TESTS = 100;

    // Static properties
    private static $instance = null;

    // Instance properties
    private $results = [];
    private $testCount = 0;
    private $startTime;
    private $enabledTests = [];

    // Private constructor for singleton
    private function __construct()
    {
        $this->startTime = microtime(true);
        $this->enabledTests = [
            'string_encryption' => true,
            'junk_code' => true,
            'shuffle_statements' => true,
            'variable_obfuscation' => true
        ];
    }

    // Singleton accessor
    public static function getInstance()
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    // Test various string patterns for encryption
    public function testStringEncryption()
    {
        // Various string patterns for testing string encryption
        $strings = [
            'simple' => 'This is a simple string',
            'quotes' => "String with 'single' and \"double\" quotes",
            'special' => "Special chars: \n \t \r \\ \$ \"\'",
            'html' => '<div class="container"><p>HTML content</p></div>',
            'unicode' => 'Unicode: 你好 नमस्ते こんにちは Привет مرحبا',
            'long' => str_repeat('Long string that should definitely be encrypted because it contains sensitive data. ', 10),
            'json' => json_encode(['key' => 'value', 'nested' => ['data' => true]]),
            'sql' => 'SELECT * FROM users WHERE email = "test@example.com" AND password = "hash"',
            'php' => '<?php echo "This looks like PHP code"; ?>',
            'multiline' => "This is a multi-line string\nWith several lines\nOf text\nTo test encoding"
        ];

        $this->logTest('String Encryption Test', function () use ($strings) {
            $results = [];
            foreach ($strings as $type => $string) {
                // Process the string somehow to prevent optimization
                $processed = strrev($string) . '|' . strlen($string);
                $results[$type] = [
                    'original_length' => strlen($string),
                    'processed' => substr($processed, 0, 20) . '...',
                    'sample' => substr($string, 0, 30) . (strlen($string) > 30 ? '...' : '')
                ];
            }
            return $results;
        });
    }

    // Test variable name obfuscation
    public function testVariableObfuscation()
    {
        $this->logTest('Variable Obfuscation Test', function () {
            // Local variables that should be obfuscated
            $userName = "John Doe";
            $userEmail = "john@example.com";
            $userAge = 30;
            $isAdmin = true;
            $userRoles = ['editor', 'subscriber'];

            // Complex variable use
            $userProfile = [
                'name' => $userName,
                'email' => $userEmail,
                'age' => $userAge,
                'is_admin' => $isAdmin,
                'roles' => $userRoles,
                'metadata' => [
                    'last_login' => time(),
                    'preferences' => [
                        'theme' => 'dark',
                        'notifications' => true
                    ]
                ]
            ];

            $formattedName = function ($name) {
                // This variable should be in a different scope
                $prefix = "User: ";
                return $prefix . $name;
            };

            return [
                'profile' => $userProfile,
                'formatted_name' => $formattedName($userName),
            ];
        });
    }

    // Test statement shuffling by using blocks of independent statements
    public function testStatementShuffling()
    {
        $this->logTest('Statement Shuffling Test', function () {
            $results = [];

            // These statements should be candidates for shuffling
            // as they are independent of each other
            $results['step1'] = "Step 1 completed";
            $results['step2'] = "Step 2 completed";
            $results['value1'] = 100;
            $results['value2'] = 200;
            $results['value3'] = 300;

            // More independent statements
            $results['hash1'] = md5('test1');
            $results['hash2'] = sha1('test2');
            $results['hash3'] = hash('sha256', 'test3');

            // Independent calculations
            $results['calc1'] = sqrt(144);
            $results['calc2'] = pow(2, 8);
            $results['calc3'] = abs(-42);

            return $results;
        });
    }

    // Test junk code by having complex logic paths
    public function testJunkCode()
    {
        $this->logTest('Junk Code Test', function () {
            $results = [];

            // This complex function has branches that will never execute
            // Perfect for junk code insertion
            for ($i = 0; $i < 10; $i++) {
                if ($i % 2 == 0) {
                    $results[] = "Even: $i";
                } else {
                    $results[] = "Odd: $i";
                }

                // This condition never evaluates to true, good insertion point
                if (false && $i > 1000) {
                    // This code would be dead code
                    $results[] = "This will never execute";
                    $impossible = sqrt(-1); // Would cause an error if executed
                }
            }

            // Another complex block with branching
            $x = 42;
            switch ($x) {
                case 10:
                    $results[] = "x is 10";
                    break;
                case 20:
                    $results[] = "x is 20";
                    break;
                case 42:
                    $results[] = "x is 42";
                    break;
                default:
                    $results[] = "x is something else";
            }

            return $results;
        });
    }

    // Test multiple features together
    public function testCombinedFeatures()
    {
        $this->logTest('Combined Features Test', function () {
            // Create a complex data structure with strings to encrypt
            $secretData = [
                'api_key' => 'sk_live_1234567890abcdefghijklmnopqrstuvwxyz',
                'auth_token' => 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjo5OTk5OTk5OTk5fQ.signature',
                'credentials' => [
                    'username' => 'admin',
                    'password' => 'super_secret_password_123!'
                ]
            ];

            // Variables to obfuscate
            $processedData = [];
            $encryptionKey = "encryption_key_" . rand(1000, 9999);
            $iterations = 1000;

            // Independent statements that could be shuffled
            $processedData['timestamp'] = time();
            $processedData['request_id'] = md5(uniqid('', true));
            $processedData['random_bytes'] = bin2hex(random_bytes(16));

            // Complex logic with branches for junk code
            for ($i = 0; $i < 5; $i++) {
                $tempKey = $encryptionKey . '_' . $i;
                $tempData = $secretData;

                // Transform data in different ways
                if ($i % 2 == 0) {
                    $tempData['processed'] = true;
                    $tempData['method'] = 'even';

                    // This will never execute - good for junk insertion
                    if (strlen($tempKey) > 1000) {
                        error_log("This should never happen");
                    }
                } else {
                    $tempData['processed'] = false;
                    $tempData['method'] = 'odd';
                }

                $processedData['iteration_' . $i] = $tempData;
            }

            // Function with its own variable scope
            $calculateHash = function ($data, $salt) {
                $intermediate = json_encode($data);
                $rounds = 5;

                for ($i = 0; $i < $rounds; $i++) {
                    $intermediate = hash('sha256', $intermediate . $salt . $i);
                }

                return $intermediate;
            };

            // Call the function
            $processedData['final_hash'] = $calculateHash($secretData, $encryptionKey);

            return $processedData;
        });
    }

    // Helper function to log test results
    private function logTest($name, $testFunction)
    {
        $this->testCount++;
        $testStart = microtime(true);

        try {
            $result = $testFunction();
            $success = true;
            $error = null;
        } catch (Exception $e) {
            $result = null;
            $success = false;
            $error = $e->getMessage();
        }

        $testEnd = microtime(true);
        $testTime = round(($testEnd - $testStart) * 1000, 2);

        $this->results[$name] = [
            'test_number' => $this->testCount,
            'success' => $success,
            'time_ms' => $testTime,
            'result' => $success ? $result : null,
            'error' => $error
        ];

        echo "Completed test: $name (" . ($success ? 'SUCCESS' : 'FAILED') . ", {$testTime}ms)\n";

        return $success;
    }

    // Run all tests
    public function runAllTests()
    {
        echo "Starting encoder feature test suite...\n";

        // Run each test
        $this->testStringEncryption();
        $this->testVariableObfuscation();
        $this->testStatementShuffling();
        $this->testJunkCode();
        $this->testCombinedFeatures();

        // Calculate total time
        $totalTime = round((microtime(true) - $this->startTime) * 1000, 2);

        echo "\nTest summary:\n";
        echo "Total tests: {$this->testCount}\n";
        echo "Total time: {$totalTime}ms\n";

        echo "\nDetailed results available in return value\n";

        // Return overall results
        return [
            'status' => 'completed',
            'tests_count' => $this->testCount,
            'total_time_ms' => $totalTime,
            'tests' => $this->results
        ];
    }
}

// Run all the tests
$testSuite = EncoderTestSuite::getInstance();
return $testSuite->runAllTests();
