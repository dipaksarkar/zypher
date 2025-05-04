#!/usr/bin/env php
<?php
/**
 * Zypher PHP File Encoder
 * 
 * This tool encodes PHP files into a custom format that can only be 
 * executed with the Zypher PHP extension installed.
 * 
 * Usage: php encode.php <source_file> [output_file] [--master-key=your_master_key] [--quiet] [--verbose]
 * If output_file is not specified, it will use source_file with _encoded.php extension
 */

// Default master key - Used to encrypt the per-file random key
define('MASTER_KEY', 'Zypher-Master-Key-X7pQ9r2s');
define('ZYPHER_SIGNATURE', 'ZYPH01');
define('DEBUG', false); // Set to true for base64 encoding (testing), false for AES encryption

/**
 * Enhanced key derivation function using HMAC-SHA256
 * 
 * @param string $masterKey The master key 
 * @param string $filename The filename used to create a file-specific key
 * @return string The derived key as a hexadecimal string
 */
function deriveFileKey($masterKey, $filename)
{
    // Use HMAC with SHA-256 to derive a file-specific key
    return hash_hmac('sha256', $filename, $masterKey);
}

// Check if source file is provided
if ($argc < 2) {
    echo "Error: No source file provided\n";
    echo "Usage: php encode.php <source_file> [output_file] [--master-key=your_master_key] [--quiet] [--verbose]\n";
    exit(1);
}

// Parse arguments
$source_file = $argv[1];
$output_file = null;
$master_key = MASTER_KEY;
$quiet_mode = false;
$verbose_mode = false;

for ($i = 2; $i < $argc; $i++) {
    if (substr($argv[$i], 0, 12) === '--master-key=') {
        $master_key = substr($argv[$i], 12);
    } elseif ($argv[$i] === '--quiet') {
        $quiet_mode = true;
    } elseif ($argv[$i] === '--verbose') {
        $verbose_mode = true;
    } elseif (!$output_file) {
        $output_file = $argv[$i];
    }
}

// Generate a random encryption key for this file - Note: length is 32 hex chars (16 bytes)
$file_key_length = 32;
$random_file_key = bin2hex(openssl_random_pseudo_bytes($file_key_length / 2));

if (!$quiet_mode || $verbose_mode) {
    echo "DEBUG: Generated random file key: '$random_file_key' (length: " . strlen($random_file_key) . ")\n";
    echo "DEBUG: Master key: '$master_key'\n";
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
    // Get filename without extension
    $path_parts = pathinfo($source_file);
    $output_file = $path_parts['dirname'] . '/' . $path_parts['filename'] . '_encoded';
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
    $encoded_content = ZYPHER_SIGNATURE . base64_encode($source_content);
    if (!$quiet_mode) {
        echo "DEBUG: Using simple base64 encoding for debugging\n";
    }
} else {
    // Generate random IVs for both content and key encryption
    $content_iv = openssl_random_pseudo_bytes(16); // IV for content encryption
    $key_iv = openssl_random_pseudo_bytes(16);     // IV for key encryption

    if (!$quiet_mode || $verbose_mode) {
        echo "DEBUG: Content IV (hex): " . bin2hex($content_iv) . " (length: " . strlen($content_iv) . ")\n";
        echo "DEBUG: Key IV (hex): " . bin2hex($key_iv) . " (length: " . strlen($key_iv) . ")\n";
    }

    // Using the base filename for key derivation is critical!
    $base_filename = basename($source_file);

    // Derive a file-specific key from master key and filename
    $derived_master_key = deriveFileKey($master_key, $base_filename);

    if (!$quiet_mode || $verbose_mode) {
        echo "DEBUG: Using base filename '$base_filename' for key derivation\n";
        echo "DEBUG: Derived master key: $derived_master_key (length: " . strlen($derived_master_key) . ")\n";
    }

    // Encrypt the random file key with the derived master key
    $encrypted_file_key = openssl_encrypt(
        $random_file_key,
        'AES-256-CBC',
        $derived_master_key,
        OPENSSL_RAW_DATA,
        $key_iv
    );

    if ($encrypted_file_key === false) {
        echo "Error: Key encryption failed: " . openssl_error_string() . "\n";
        exit(1);
    }

    if ($verbose_mode) {
        echo "DEBUG: Random file key to encrypt: " . $random_file_key . "\n";
        echo "DEBUG: Derived master key for encryption: " . $derived_master_key . "\n";
        echo "DEBUG: Encrypted file key (hex): " . bin2hex($encrypted_file_key) . "\n";
    }

    // Encrypt the file content using the random file key
    $encrypted_content = openssl_encrypt(
        $source_content,
        'AES-256-CBC',
        $random_file_key,
        OPENSSL_RAW_DATA,
        $content_iv
    );

    if ($encrypted_content === false) {
        echo "Error: Content encryption failed: " . openssl_error_string() . "\n";
        exit(1);
    }

    if (!$quiet_mode || $verbose_mode) {
        echo "DEBUG: Encrypted file key length: " . strlen($encrypted_file_key) . " bytes\n";
        echo "DEBUG: Encrypted content size: " . strlen($encrypted_content) . " bytes\n";
    }

    // Format:
    // - 16 bytes: content IV
    // - 16 bytes: key IV
    // - 4 bytes: encrypted file key length (big endian)
    // - N bytes: encrypted file key
    // - 1 byte: original filename length
    // - M bytes: original filename (for key derivation)
    // - Remaining bytes: encrypted content
    $key_length = strlen($encrypted_file_key);
    $key_length_bytes = pack("N", $key_length); // 4 bytes unsigned long (big endian)

    // Save original base filename for key derivation
    $orig_filename = basename($source_file);
    $filename_length = strlen($orig_filename);

    if ($verbose_mode) {
        echo "DEBUG: Including original filename '$orig_filename' (length: $filename_length) for key derivation\n";
    }

    // Pack everything together
    $final_content = $content_iv . $key_iv . $key_length_bytes . $encrypted_file_key .
        chr($filename_length) . $orig_filename . $encrypted_content;

    // Base64 encode the entire package
    $encoded_content = base64_encode($final_content);

    // Add signature to identify this as a Zypher encoded file
    $encoded_content = ZYPHER_SIGNATURE . $encoded_content;
}

// Write the encoded content directly to the output file without PHP tags
// This is crucial for our extension to see the ZYPH01 signature first
if (file_put_contents($output_file, $encoded_content) === false) {
    echo "Error: Could not write to output file '$output_file'\n";
    exit(1);
}

// Create a PHP wrapper script that includes our encoded file
$wrapper_path = $output_file . ".php";
$wrapper_content = <<<EOT
<?php
// Zypher encoded file wrapper
// This wrapper ensures the Zypher extension is loaded before processing the encoded file
if(!extension_loaded('zypher')){
    echo "\\nScript error: the Zypher Loader for PHP needs to be installed.\\n";
    echo "The Zypher Loader is the industry standard PHP extension for running protected PHP code,\\n";
    echo "and can usually be added easily to a PHP installation.\\n";
    exit(199);
}

// The encoded file will be processed by the Zypher extension
include(__DIR__ . '/' . basename('$output_file'));
EOT;

if (file_put_contents($wrapper_path, $wrapper_content) === false) {
    echo "Error: Could not write to wrapper file '$wrapper_path'\n";
    exit(1);
}

if (!$quiet_mode) {
    echo "File encoded successfully!\n";
    echo "Source: $source_file\n";
    echo "Encoded file: $output_file\n";
    echo "Wrapper file: $wrapper_path\n";
    if (!DEBUG) {
        echo "Encryption: AES-256-CBC with secure key derivation and two-layer encryption\n";
    } else {
        echo "Encryption: Base64 (debug mode)\n";
    }
    echo "To run the encoded file, use: php $wrapper_path\n";
}

exit(0);
