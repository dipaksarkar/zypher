#!/usr/bin/env php
<?php
/**
 * Zypher PHP File Encoder
 * 
 * This tool encodes PHP files into a custom format (.php) that can only be 
 * executed with the Zypher PHP extension installed.
 * 
 * Usage: php encode.php <source_file> [output_file] [--master-key=your_master_key] [--quiet]
 * If output_file is not specified, it will use source_file with _encoded.php extension
 */

// Default master key - Used to encrypt the per-file random key
define('MASTER_KEY', 'Zypher-Master-Key-X7pQ9r2s');
define('DEBUG', false); // Set to false for AES encryption

// The stub that will be prepended to the encoded file - make sure it contains exactly "the Zypher Loader for PHP" for tests
define('ZYPHER_STUB', '<?php 
if(!extension_loaded(\'zypher\')){echo("\nScript error: the Zypher Loader for PHP needs to be installed.\n\nThe Zypher Loader is the industry standard PHP extension for running protected PHP code,\nand can usually be added easily to a PHP installation.\n\nFor Loaders please visit".(php_sapi_name()==\'cli\'?":\n\nhttps://get-loader.zypher.com\n\nFor":\' <a href="https://get-loader.zypher.com">get-loader.zypher.com</a> and for\')." an instructional video please see".(php_sapi_name()==\'cli\'?":\n\nhttp://zypher.be/LV\n\n":\' <a href="http://zypher.be/LV">http://zypher.be/LV</a> \')."\n\n");exit(199);}
?>
');

// Check if source file is provided
if ($argc < 2) {
    echo "Error: No source file provided\n";
    echo "Usage: php encode.php <source_file> [output_file] [--master-key=your_master_key] [--quiet]\n";
    exit(1);
}

// Parse arguments
$source_file = $argv[1];
$output_file = null;
$master_key = MASTER_KEY;
$quiet_mode = false;

for ($i = 2; $i < $argc; $i++) {
    if (substr($argv[$i], 0, 12) === '--master-key=') {
        $master_key = substr($argv[$i], 12);
    } elseif ($argv[$i] === '--quiet') {
        $quiet_mode = true;
    } elseif (!$output_file) {
        $output_file = $argv[$i];
    }
}

// Generate a random encryption key for this file
$file_key_length = 32; // 256 bits for AES-256
$random_file_key = bin2hex(openssl_random_pseudo_bytes($file_key_length / 2));

if (DEBUG) {
    echo "DEBUG: Generated file key: '$random_file_key'\n";
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
    $output_file = $path_parts['dirname'] . '/' . $path_parts['filename'] . '_encoded.php';
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
    if (!$quiet_mode) {
        echo "DEBUG: Using simple base64 encoding for debugging\n";
    }
} else {
    // Use a randomized IV for better security
    $iv = openssl_random_pseudo_bytes(16);

    if (DEBUG) {
        echo "DEBUG: IV (hex): " . bin2hex($iv) . "\n";
        echo "DEBUG: IV length: " . strlen($iv) . " bytes\n";
    }

    // Encrypt the file content using the random file key
    $encrypted_content = openssl_encrypt(
        $source_content,
        'AES-256-CBC',
        $random_file_key,
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($encrypted_content === false) {
        echo "Error: Encryption failed: " . openssl_error_string() . "\n";
        exit(1);
    }

    // Now encrypt the random file key with the master key
    $master_iv = substr(md5($master_key, true), 0, 16); // Derive IV from master key
    $padded_master_key = substr(hash('sha256', $master_key, true), 0, 32);
    $encrypted_file_key = openssl_encrypt(
        $random_file_key,
        'AES-256-CBC',
        $padded_master_key,
        OPENSSL_RAW_DATA,
        $master_iv
    );

    if ($encrypted_file_key === false) {
        echo "Error: Key encryption failed: " . openssl_error_string() . "\n";
        exit(1);
    }

    if (DEBUG) {
        echo "DEBUG: Encrypted file key (hex): " . bin2hex($encrypted_file_key) . "\n";
        echo "DEBUG: Encrypted content size: " . strlen($encrypted_content) . " bytes\n";
    }

    // Format: 
    // - 16 bytes: content IV
    // - 16 bytes: key IV (master_iv)
    // - 4 bytes: encrypted file key length
    // - N bytes: encrypted file key
    // - Remaining bytes: encrypted content
    $key_length = strlen($encrypted_file_key);
    $key_length_bytes = pack("N", $key_length); // 4 bytes unsigned long (big endian)

    $final_content = $iv . $master_iv . $key_length_bytes . $encrypted_file_key . $encrypted_content;

    // Base64 encode the entire thing for storage
    $encoded_content = base64_encode($final_content);

    // Add a signature to identify this as a Zypher encoded file
    $encoded_content = "ZYPH02" . $encoded_content; // New version with embedded key
}

// Prepend the stub to the encoded content
$complete_content = ZYPHER_STUB . $encoded_content;

// Save the encoded content
if (file_put_contents($output_file, $complete_content) === false) {
    echo "Error: Could not write to output file '$output_file'\n";
    exit(1);
}

if (!$quiet_mode) {
    echo "File encoded successfully!\n";
    echo "Source: $source_file\n";
    echo "Output: $output_file\n";
    if (!DEBUG) {
        echo "Encryption: AES-256-CBC with secure random key\n";
    } else {
        echo "Encryption: Base64 (debug mode)\n";
    }
}

exit(0);
