#!/usr/bin/env php
<?php
/**
 * Zypher PHP File Encoder
 * 
 * This tool encodes PHP files into a custom format (.penc) that can only be 
 * executed with the Zypher PHP extension installed.
 * 
 * Usage: php encode.php <source_file> [output_file] [--key=your_encryption_key]
 * If output_file is not specified, it will use source_file with .penc extension
 */

// Default encryption key - THIS SHOULD BE CHANGED IN PRODUCTION
define('DEFAULT_KEY', 'TestKey123');
define('DEBUG', false); // Set to false for AES encryption

// Check if source file is provided
if ($argc < 2) {
    echo "Error: No source file provided\n";
    echo "Usage: php encode.php <source_file> [output_file] [--key=your_encryption_key]\n";
    exit(1);
}

// Parse arguments
$source_file = $argv[1];
$output_file = null;
$encryption_key = DEFAULT_KEY;

for ($i = 2; $i < $argc; $i++) {
    if (substr($argv[$i], 0, 6) === '--key=') {
        $encryption_key = substr($argv[$i], 6);
    } elseif (!$output_file) {
        $output_file = $argv[$i];
    }
}

if (DEBUG) {
    echo "DEBUG: Using encryption key: '$encryption_key'\n";
    echo "DEBUG: Key length: " . strlen($encryption_key) . " bytes\n";
    echo "DEBUG: Key binary representation: " . bin2hex($encryption_key) . "\n";
}

// Validate source file
if (!file_exists($source_file)) {
    echo "Error: Source file '$source_file' does not exist\n";
    exit(1);
}

if (!is_readable($source_file)) {
    echo "Error: Source file '$source_file' is not readable\n";
    exit(1);
}

// Determine output file path
if (!$output_file) {
    // If source file already has .penc extension, append another one
    if (substr($source_file, -5) === '.penc') {
        $output_file = $source_file . '.penc';
    } else {
        // Replace .php extension with .penc or append .penc
        $path_parts = pathinfo($source_file);
        if (isset($path_parts['extension']) && $path_parts['extension'] === 'php') {
            $output_file = $path_parts['dirname'] . '/' . $path_parts['filename'] . '.penc';
        } else {
            $output_file = $source_file . '.penc';
        }
    }
}

// Read the source file
$source_content = file_get_contents($source_file);
if ($source_content === false) {
    echo "Error: Could not read source file '$source_file'\n";
    exit(1);
}

// Use a simpler encryption for debugging
if (DEBUG) {
    // For testing, use simple base64 instead of AES to ensure the extension works
    $encoded_content = "ZYPH00" . base64_encode($source_content);
    echo "DEBUG: Using simple base64 encoding for debugging\n";
} else {
    // Use fixed IV for simplicity (in production, should be random and securely stored)
    $iv = str_repeat('X', 16); // 16 bytes of 'X' for a fixed IV

    if (DEBUG) {
        echo "DEBUG: IV (hex): " . bin2hex($iv) . "\n";
        echo "DEBUG: IV length: " . strlen($iv) . " bytes\n";
    }

    // Ensure the key is exactly 32 bytes (256 bits) for AES-256
    $padded_key = str_pad($encryption_key, 32, '#');

    // Normal AES-256-CBC encryption for production with key/iv info
    $encrypted_content = openssl_encrypt(
        $source_content,
        'AES-256-CBC',
        $padded_key,
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($encrypted_content === false) {
        echo "Error: Encryption failed: " . openssl_error_string() . "\n";
        exit(1);
    }

    if (DEBUG) {
        echo "DEBUG: Padded key (hex): " . bin2hex($padded_key) . " (length: " . strlen($padded_key) . ")\n";
        echo "DEBUG: Encrypted content size: " . strlen($encrypted_content) . " bytes\n";
    }

    // Format: 16 bytes of IV followed by the encrypted content
    $final_content = $iv . $encrypted_content;

    // Base64 encode the entire thing for storage
    $encoded_content = base64_encode($final_content);

    // Add a signature to identify this as a Zypher encoded file
    $encoded_content = "ZYPH01" . $encoded_content;
}

// Save the encoded content
if (file_put_contents($output_file, $encoded_content) === false) {
    echo "Error: Could not write to output file '$output_file'\n";
    exit(1);
}

echo "File encoded successfully!\n";
echo "Source: $source_file\n";
echo "Output: $output_file\n";
if (!DEBUG) {
    echo "Encryption: AES-256-CBC with fixed IV\n";
} else {
    echo "Encryption: Base64 (debug mode)\n";
}

exit(0);
