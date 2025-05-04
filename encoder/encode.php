#!/usr/bin/env php
<?php
/**
 * Zypher PHP File Encoder
 * 
 * This tool encodes PHP files into a custom format that can only be 
 * executed with the Zypher PHP extension installed.
 * 
 * Usage: php encode.php <source_file> [output_file] [--master-key=your_master_key] [--quiet] [--verbose]
 *        [--obfuscate] [--shuffle-stmts] [--junk-code] [--string-encryption]
 * If output_file is not specified, it will use source_file with _encoded.php extension
 */

// Default master key - Used to encrypt the per-file random key
define('MASTER_KEY', 'Zypher-Master-Key-X7pQ9r2s');
define('ZYPHER_SIGNATURE', 'ZYPH01');
define('DEBUG', false); // Set to true for base64 encoding (testing), false for AES encryption

/**
 * Enhanced key derivation function using HMAC-SHA256 with multiple iterations
 * 
 * @param string $masterKey The master key 
 * @param string $filename The filename used to create a file-specific key
 * @param int $iterations Number of HMAC iterations for key strengthening
 * @return string The derived key as a hexadecimal string
 */
function deriveFileKey($masterKey, $filename, $iterations = 1000)
{
    // Add a salt based on a combination of factors 
    $salt = 'ZypherSalt-' . md5($filename);

    // Initial key derivation
    $derivedKey = hash_hmac('sha256', $filename . $salt, $masterKey, true);

    // Multiple iterations to strengthen against brute force
    for ($i = 0; $i < $iterations; $i++) {
        $derivedKey = hash_hmac('sha256', $derivedKey . $salt . chr($i & 0xFF), $masterKey, true);
    }

    return bin2hex($derivedKey);
}

/**
 * String encryption function to obfuscate string literals in the code
 * 
 * @param string $str The string to encrypt
 * @param string $key Encryption key
 * @return string PHP function call that will decode the string using the native extension
 */
function obfuscateString($str, $key)
{
    // XOR encryption with rotating key
    $result = '';
    $keyLen = strlen($key);
    for ($i = 0; $i < strlen($str); $i++) {
        $result .= chr(ord($str[$i]) ^ ord($key[$i % $keyLen]));
    }

    // Convert to hex representation
    $hex = bin2hex($result);

    // Use the native extension function to decode string at runtime
    return 'zypher_decode_string("' . $hex . '", "' . md5($key) . '")';
}

/**
 * Generate the string decoder function to include in obfuscated code
 * 
 * @return string PHP code with the decoder function
 */
function generateStringDecoderFunction()
{
    return <<<'EOD'
function zypher_decode_str($hex, $key) {
    $bin = hex2bin($hex);
    $result = '';
    $keyLen = strlen($key);
    for ($i = 0; $i < strlen($bin); $i++) {
        $result .= chr(ord($bin[$i]) ^ ord($key[$i % $keyLen]));
    }
    return $result;
}
EOD;
}

/**
 * Transform PHP code by obfuscating variable names, adding junk code, etc.
 *
 * @param string $code PHP source code
 * @param array $options Obfuscation options
 * @return string Obfuscated PHP code
 */
function obfuscateCode($code, $options)
{
    // Only proceed if we have tokenizer extension
    if (!extension_loaded('tokenizer')) {
        echo "Warning: Tokenizer extension not available, skipping code obfuscation\n";
        return $code;
    }

    // Parse PHP tokens
    $tokens = token_get_all($code);
    $obfuscatedCode = '';

    // Variables to track scope and names
    $variables = [];
    $functions = [];
    $obfuscatedMap = [];

    // First pass: Identify variables and functions
    foreach ($tokens as $token) {
        if (is_array($token) && $token[0] === T_VARIABLE) {
            $variables[$token[1]] = true;
        }
        if (is_array($token) && $token[0] === T_FUNCTION) {
            // Track function names (simplistic approach)
            // In real implementation, we'd use more sophisticated parsing
        }
    }

    // Create obfuscated names
    foreach ($variables as $var => $dummy) {
        if ($var !== '$this' && !preg_match('/^\$_/', $var)) { // Skip $this and superglobals
            $obfuscatedMap[$var] = '$' . '_' . md5($var . mt_rand());
        }
    }

    // Check if PHP extension has the required function
    if ($options['string_encryption']) {
        // Add validation code at the beginning
        $obfuscatedCode = "<?php\n";
        $obfuscatedCode .= "if (!function_exists('zypher_decode_string')) {\n";
        $obfuscatedCode .= "    trigger_error('Zypher extension missing or outdated - string decoding function not available', E_USER_ERROR);\n";
        $obfuscatedCode .= "}\n\n";

        // If there's a PHP opening tag in the original code, remove it to avoid duplication
        if (strpos($code, '<?php') === 0) {
            $code = substr($code, 5);
        }
    } else {
        // If no string encryption is used, we still need to preserve the PHP tag
        if (strpos($code, '<?php') === 0) {
            $obfuscatedCode = "<?php";
            $code = substr($code, 5);
        }
    }

    // Second pass: Replace names with obfuscated versions
    foreach ($tokens as $token) {
        if (is_array($token)) {
            $tokenType = $token[0];
            $tokenValue = $token[1];

            // Replace variable names
            if ($tokenType === T_VARIABLE && isset($obfuscatedMap[$tokenValue])) {
                $obfuscatedCode .= $obfuscatedMap[$tokenValue];
            }
            // Optionally encrypt strings
            else if ($options['string_encryption'] && $tokenType === T_CONSTANT_ENCAPSED_STRING) {
                // Remove quotes
                $str = substr($tokenValue, 1, -1);
                // Only encrypt strings above certain length to avoid overhead
                if (strlen($str) > 3 && !preg_match('/^[0-9.]+$/', $str)) {
                    $obfuscatedCode .= obfuscateString($str, 'zypher-key');
                } else {
                    $obfuscatedCode .= $tokenValue;
                }
            } else {
                $obfuscatedCode .= $tokenValue;
            }
        } else {
            $obfuscatedCode .= $token;
        }
    }

    // Add junk code if option enabled
    if ($options['junk_code']) {
        $junk = generateJunkCode();

        // If we've already added code, don't add PHP tag again
        if (strpos($obfuscatedCode, '<?php') !== 0) {
            $obfuscatedCode = "<?php " . $junk . $obfuscatedCode;
        } else {
            // Insert after PHP tag
            $obfuscatedCode = "<?php " . $junk . substr($obfuscatedCode, 5);
        }

        // Insert at various positions (simplified approach)
        $parts = preg_split('/;/', $obfuscatedCode, -1, PREG_SPLIT_DELIM_CAPTURE);
        $result = '';
        foreach ($parts as $i => $part) {
            $result .= $part;
            if ($i % 5 === 0 && $i > 0) { // Every 5th statement
                $result .= generateJunkCode();
            }
        }
        $obfuscatedCode = $result;
    }

    return $obfuscatedCode;
}

/**
 * Generate meaningless code that will be eliminated by the optimizer
 */
function generateJunkCode()
{
    $junkFunctions = [
        'if(false){$_x=array();foreach($_x as $k=>$v){echo $k;}}',
        '$_t=microtime();if(false&&$_t){eval("return false;");}',
        'function _z' . mt_rand() . '(){return false;} /* junk function */',
        '$_a=array();$_a[]=1;$_a[]=2;if(count($_a)>999){$_a=array_reverse($_a);}',
    ];

    return $junkFunctions[array_rand($junkFunctions)];
}

// Check if source file is provided
if ($argc < 2) {
    echo "Error: No source file provided\n";
    echo "Usage: php encode.php <source_file> [output_file] [--master-key=your_master_key] [--quiet] [--verbose]\n";
    echo "       [--obfuscate] [--shuffle-stmts] [--junk-code] [--string-encryption]\n";
    exit(1);
}

// Parse arguments
$source_file = $argv[1];
$output_file = null;
$master_key = MASTER_KEY;
$quiet_mode = false;
$verbose_mode = false;

// Obfuscation options
$obfuscation_options = [
    'enabled' => false,
    'shuffle_statements' => false,
    'junk_code' => false,
    'string_encryption' => false,
];

for ($i = 2; $i < $argc; $i++) {
    if (substr($argv[$i], 0, 12) === '--master-key=') {
        $master_key = substr($argv[$i], 12);
    } elseif ($argv[$i] === '--quiet') {
        $quiet_mode = true;
    } elseif ($argv[$i] === '--verbose') {
        $verbose_mode = true;
    } elseif ($argv[$i] === '--obfuscate') {
        $obfuscation_options['enabled'] = true;
    } elseif ($argv[$i] === '--shuffle-stmts') {
        $obfuscation_options['shuffle_statements'] = true;
    } elseif ($argv[$i] === '--junk-code') {
        $obfuscation_options['junk_code'] = true;
    } elseif ($argv[$i] === '--string-encryption') {
        $obfuscation_options['string_encryption'] = true;
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

// Apply code obfuscation if enabled
if ($obfuscation_options['enabled']) {
    if (!$quiet_mode) {
        echo "Applying code obfuscation techniques...\n";
    }
    $source_content = obfuscateCode($source_content, [
        'string_encryption' => $obfuscation_options['string_encryption'],
        'junk_code' => $obfuscation_options['junk_code']
    ]);

    if ($verbose_mode) {
        echo "DEBUG: Code obfuscation completed.\n";
    }
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

    // Add a timing protection factor - use an expensive key derivation
    $start_time = microtime(true);

    // Derive a file-specific key from master key and filename
    $derived_master_key = deriveFileKey($master_key, $base_filename, 1000); // Increased iterations

    $end_time = microtime(true);
    if ($verbose_mode) {
        echo "DEBUG: Key derivation took " . round(($end_time - $start_time) * 1000, 2) . " ms\n";
    }

    if (!$quiet_mode || $verbose_mode) {
        echo "DEBUG: Using base filename '$base_filename' for key derivation\n";
        echo "DEBUG: Derived master key: $derived_master_key (length: " . strlen($derived_master_key) . ")\n";
    }

    // Add checksum for integrity checking - helps detect tampering
    $checksum = md5($source_content);

    // Integrity: Add timestamp to prevent replay attacks if that were a concern
    $timestamp = time();
    $timestamp_bytes = pack("N", $timestamp);

    // Add version marker for future compatibility
    $version = 1; // Version of the encoding format
    $version_byte = chr($version);

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

    // Now include checksum in the content to be encrypted
    $content_to_encrypt = $checksum . $source_content;

    // Encrypt the file content using the random file key
    $encrypted_content = openssl_encrypt(
        $content_to_encrypt,
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

    // Enhanced Format:
    // - 1 byte: version marker
    // - 4 bytes: timestamp (for anti-replay)
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
        echo "DEBUG: Added version marker: $version\n";
        echo "DEBUG: Added timestamp: $timestamp\n";
        echo "DEBUG: Added content checksum: $checksum\n";
    }

    // Pack everything together with new format elements
    $final_content = $version_byte . $timestamp_bytes . $content_iv . $key_iv .
        $key_length_bytes . $encrypted_file_key .
        chr($filename_length) . $orig_filename . $encrypted_content;

    // Add an additional layer of obfuscation - rotate bytes
    $rotated_content = '';
    for ($i = 0; $i < strlen($final_content); $i++) {
        $rotated_content .= chr((ord($final_content[$i]) + 7) & 0xFF);
    }

    // Base64 encode the entire package
    $encoded_content = base64_encode($rotated_content);

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

// Add anti-debugging check
if (function_exists('xdebug_get_code_coverage') || 
    extension_loaded('xdebug') ||
    ini_get('assert.active') == 1) {
    echo "\\nError: Debugging tools detected.\\n";
    echo "This protected code cannot run under a debugger.\\n";
    exit(403);
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
        if ($obfuscation_options['enabled']) {
            echo "Applied obfuscation: ";
            $techniques = [];
            if ($obfuscation_options['string_encryption']) $techniques[] = "string encryption";
            if ($obfuscation_options['junk_code']) $techniques[] = "junk code insertion";
            if ($obfuscation_options['shuffle_statements']) $techniques[] = "statement shuffling";
            echo implode(", ", $techniques) . "\n";
        }
    } else {
        echo "Encryption: Base64 (debug mode)\n";
    }
    echo "To run the encoded file, use: php $wrapper_path\n";
}

exit(0);
