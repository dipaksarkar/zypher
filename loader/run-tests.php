#!/usr/bin/env php
<?php
/**
 * Zypher PHP Loader Test Runner
 * 
 * This script is used to run PHP tests for the Zypher extension.
 */

// Find PHP executable
$php_executable = getenv('TEST_PHP_EXECUTABLE');
if (!$php_executable) {
    $php_executable = exec('which php');
    if (!$php_executable) {
        $php_executable = '/usr/bin/php'; // Fallback
    }
    // Export it for the test runner
    putenv("TEST_PHP_EXECUTABLE=$php_executable");
}

echo "Using PHP executable: $php_executable\n";

// Create a temporary PHP.ini file with license configuration
$php_ini = __DIR__ . '/tmp-php.ini';
$extension_path = __DIR__ . '/modules/zypher.so';
$license_path = __DIR__ . '/../licenses/license.key';

$ini_content = <<<INI
extension=$extension_path
zypher.license_path = $license_path
zypher.encryption_key = TestKey123
zypher.license_check_enabled = 0
INI;

file_put_contents($php_ini, $ini_content);

echo "Created temporary php.ini at $php_ini\n";
echo "Extension path: $extension_path\n";
echo "License path: $license_path\n";

// Run each test file individually with proper configuration
$test_files = glob(__DIR__ . '/tests/*.phpt');
$success_count = 0;
$fail_count = 0;

echo "Running " . count($test_files) . " test cases...\n\n";

foreach ($test_files as $test_file) {
    $test_name = basename($test_file);
    echo "Testing: $test_name\n";

    // Run the test using the PHP executable with our configuration
    $command = "$php_executable -n -c $php_ini $test_file";
    echo "Command: $command\n";

    $output = [];
    $return_var = 0;
    exec($command, $output, $return_var);

    // Display test output
    echo implode("\n", $output) . "\n";

    if ($return_var === 0) {
        echo "TEST PASSED: $test_name\n\n";
        $success_count++;
    } else {
        echo "TEST FAILED: $test_name\n\n";
        $fail_count++;
    }
}

// Clean up
@unlink($php_ini);

// Report results
echo "==============================================\n";
echo "Test Results:\n";
echo "  Passed: $success_count\n";
echo "  Failed: $fail_count\n";
echo "  Total: " . count($test_files) . "\n";
echo "==============================================\n";

exit($fail_count > 0 ? 1 : 0);
