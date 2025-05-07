<?php

/**
 * Zypher Opcode Debug Utility
 * 
 * This tool helps to decode and visualize .opcodes files in a readable format
 * for debugging purposes. It parses the base64-encoded serialized data and
 * displays the opcodes in a structured way.
 */

if ($argc < 2) {
    echo "Usage: php opcode_debug.php <opcode_file>\n";
    echo "Example: php opcode_debug.php advanced.php.opcodes\n";
    exit(1);
}

$opcodeFile = $argv[1];
if (!file_exists($opcodeFile)) {
    echo "Error: File not found: $opcodeFile\n";
    exit(1);
}

// Read the opcode file content
$content = file_get_contents($opcodeFile);
if (empty($content)) {
    echo "Error: Empty opcode file\n";
    exit(1);
}

// Try to decode base64
$decoded = base64_decode($content, true);
if ($decoded === false) {
    echo "Error: Content is not valid base64 data\n";
    exit(1);
}

// Try to unserialize the data
$data = @unserialize($decoded);
if ($data === false) {
    echo "Error: Could not unserialize the data. It might be encrypted or corrupted.\n";
    exit(1);
}

// Helper function to display the data in a more readable format
function displayData($data, $indent = 0)
{
    $indentStr = str_repeat("    ", $indent);

    if (is_array($data)) {
        foreach ($data as $key => $value) {
            if (is_array($value) || is_object($value)) {
                echo "$indentStr$key:\n";
                displayData($value, $indent + 1);
            } else {
                // For binary data or large strings, show a preview
                if (is_string($value) && strlen($value) > 100) {
                    $preview = substr($value, 0, 100) . "... (" . strlen($value) . " bytes)";
                    echo "$indentStr$key: $preview\n";
                } else {
                    echo "$indentStr$key: " . print_r($value, true) . "\n";
                }
            }
        }
    } elseif (is_object($data)) {
        echo "$indentStr" . get_class($data) . " Object:\n";
        displayData((array)$data, $indent + 1);
    } else {
        echo "$indentStr" . print_r($data, true) . "\n";
    }
}

// Display file information
echo "=== Zypher Opcode Debug Utility ===\n\n";
echo "File: $opcodeFile\n";
echo "Size: " . filesize($opcodeFile) . " bytes\n\n";

// Display the opcode structure
echo "=== Opcode Structure ===\n\n";
displayData($data);

// If compilation_success is false, show the error
if (isset($data['compilation_success']) && $data['compilation_success'] === false) {
    echo "\n=== Compilation Error ===\n";
    echo $data['compilation_error'] . "\n";
}

// Display a sample of the original source code if available
if (isset($data['contents']) && !empty($data['contents'])) {
    $sourcePreview = substr($data['contents'], 0, 200);
    echo "\n=== Source Code Preview ===\n";
    echo "$sourcePreview...\n";
}

// Show basic stats
echo "\n=== Statistics ===\n";
echo "File: {$data['filename']}\n";
if (isset($data['timestamp'])) {
    echo "Timestamp: " . date('Y-m-d H:i:s', $data['timestamp']) . "\n";
}
if (isset($data['php_version'])) {
    echo "PHP Version: {$data['php_version']}\n";
}
if (isset($data['compiled_with'])) {
    echo "Compiled with: {$data['compiled_with']}\n";
}
