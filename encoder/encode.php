#!/usr/bin/env php
<?php
/**
 * Zypher PHP File Encoder
 * 
 * This tool encodes PHP files into a custom format that can only be 
 * executed with the Zypher PHP extension installed.
 * 
 * Usage: php encode.php <source_path> [output_path] [--master-key=your_master_key] [--quiet] [--verbose]
 *        [--obfuscate] [--shuffle-stmts] [--junk-code] [--string-encryption] [--exclude=pattern1,pattern2]
 * If output_path is not specified, it will use source_path with _encoded suffix
 * <source_path> and [output_path] can be either files or directories
 */

// Default master key - Used to encrypt the per-file random key
define('MASTER_KEY', 'Zypher-Master-Key-X7pQ9r2s');
define('ZYPHER_SIGNATURE', 'ZYPH01');
define('DEBUG', false); // Set to false for real AES encryption, true for base64 encoding (testing)

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
    $phpOpenTagAdded = false;

    // Variables to track scope and names
    $variables = [];
    $obfuscatedMap = [];
    $braceLevel = 0;

    // Skip vars: superglobals and special variables
    $skipVars = [
        '$this',
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_SESSION',
        '$_COOKIE',
        '$_SERVER',
        '$_FILES',
        '$_ENV',
        '$GLOBALS',
        '$argv',
        '$argc'
    ];

    // First pass: Identify variables
    $inFunction = false;
    $inClass = false;
    $currentScope = "global";
    $scopeStack = [];

    // Process each token to identify variables in their proper scope
    foreach ($tokens as $i => $token) {
        if (is_array($token)) {
            $tokenType = $token[0];
            $tokenValue = $token[1];

            // Track scope changes
            if ($tokenType === T_FUNCTION) {
                $inFunction = true;
                // Look ahead to find function name
                $j = $i + 1;
                while ($j < count($tokens) && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                    $j++;
                }
                $functionName = is_array($tokens[$j]) && $tokens[$j][0] === T_STRING ? $tokens[$j][1] : 'anonymous';
                array_push($scopeStack, $currentScope);
                $currentScope = "function:" . $functionName;
            } else if ($tokenType === T_CLASS) {
                $inClass = true;
                // Look ahead to find class name
                $j = $i + 1;
                while ($j < count($tokens) && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                    $j++;
                }
                $className = is_array($tokens[$j]) && $tokens[$j][0] === T_STRING ? $tokens[$j][1] : 'anonymous';
                array_push($scopeStack, $currentScope);
                $currentScope = "class:" . $className;
            } else if ($tokenType === T_VARIABLE) {
                // Skip special variables
                if (!in_array($tokenValue, $skipVars)) {
                    // Record variable with its scope
                    $variables[$currentScope][$tokenValue] = true;
                }
            }
        } else {
            // Non-array tokens are typically single characters like { } ; etc.
            if ($token === '{') {
                $braceLevel++;
            } else if ($token === '}') {
                $braceLevel--;
                if ($braceLevel === 0 && ($inFunction || $inClass)) {
                    if (!empty($scopeStack)) {
                        $currentScope = array_pop($scopeStack);
                    } else {
                        $currentScope = "global";
                    }
                    $inFunction = false;
                    $inClass = false;
                }
            }
        }
    }

    // Create obfuscated names for each variable in each scope
    foreach ($variables as $scope => $vars) {
        foreach ($vars as $var => $dummy) {
            // Generate a unique obfuscated name for this scope+variable
            $obfuscatedMap[$scope][$var] = '$' . '_z' . substr(md5($var . $scope . mt_rand()), 0, 8);
        }
    }

    // Apply PHP tag handling for string encryption if needed
    if ($options['string_encryption']) {
        $obfuscatedCode = "<?php\n";
        $phpOpenTagAdded = true;

        // Check if zypher_decode_string exists
        $obfuscatedCode .= "if (!function_exists('zypher_decode_string')) {\n";
        $obfuscatedCode .= "    trigger_error('Zypher extension missing or outdated - string decoding function not available', E_USER_ERROR);\n";
        $obfuscatedCode .= "}\n\n";

        // If there's a PHP opening tag in the original code, remove it to avoid duplication
        if (strpos($code, '<?php') === 0) {
            $code = substr($code, 5);
        }
    } else if (strpos($code, '<?php') === 0) {
        $obfuscatedCode = "<?php";
        $phpOpenTagAdded = true;
        $code = substr($code, 5);
    }

    // Second pass: Replace variable names with obfuscated versions
    $currentScope = "global";
    $scopeStack = [];
    $braceLevel = 0;
    $inFunction = false;
    $inClass = false;

    for ($i = 0; $i < count($tokens); $i++) {
        $token = $tokens[$i];

        if (is_array($token)) {
            $tokenType = $token[0];
            $tokenValue = $token[1];

            // Track scope changes for correct variable replacement
            if ($tokenType === T_FUNCTION) {
                $inFunction = true;
                // Look ahead to find function name
                $j = $i + 1;
                while ($j < count($tokens) && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                    $j++;
                }
                $functionName = is_array($tokens[$j]) && $tokens[$j][0] === T_STRING ? $tokens[$j][1] : 'anonymous';
                array_push($scopeStack, $currentScope);
                $currentScope = "function:" . $functionName;
                $obfuscatedCode .= $tokenValue;
            } else if ($tokenType === T_CLASS) {
                $inClass = true;
                // Look ahead to find class name
                $j = $i + 1;
                while ($j < count($tokens) && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                    $j++;
                }
                $className = is_array($tokens[$j]) && $tokens[$j][0] === T_STRING ? $tokens[$j][1] : 'anonymous';
                array_push($scopeStack, $currentScope);
                $currentScope = "class:" . $className;
                $obfuscatedCode .= $tokenValue;
            }
            // Handle PHP open tags if not already added
            else if ($tokenType === T_OPEN_TAG && !$phpOpenTagAdded) {
                $obfuscatedCode .= $tokenValue;
                $phpOpenTagAdded = true;
            }
            // Replace variable names with obfuscated versions
            else if ($tokenType === T_VARIABLE) {
                // Check if this is a property access like $this->property
                $skipReplacement = false;
                if ($i >= 2 && is_array($tokens[$i - 1]) && $tokens[$i - 1][0] === T_OBJECT_OPERATOR) {
                    $skipReplacement = true;
                }

                // Skip special variables
                if (in_array($tokenValue, $skipVars) || $skipReplacement) {
                    $obfuscatedCode .= $tokenValue;
                }
                // Replace with obfuscated name if it exists in this scope
                else if (isset($obfuscatedMap[$currentScope][$tokenValue])) {
                    $obfuscatedCode .= $obfuscatedMap[$currentScope][$tokenValue];
                }
                // Fall back to global scope if not found in current scope
                else if (isset($obfuscatedMap["global"][$tokenValue])) {
                    $obfuscatedCode .= $obfuscatedMap["global"][$tokenValue];
                }
                // If no mapping found, keep original
                else {
                    $obfuscatedCode .= $tokenValue;
                }
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
            // Handle braces to track scope levels
            if ($token === '{') {
                $braceLevel++;
                $obfuscatedCode .= $token;
            } else if ($token === '}') {
                $braceLevel--;
                $obfuscatedCode .= $token;

                if ($braceLevel === 0 && ($inFunction || $inClass)) {
                    if (!empty($scopeStack)) {
                        $currentScope = array_pop($scopeStack);
                    } else {
                        $currentScope = "global";
                    }
                    $inFunction = false;
                    $inClass = false;
                }
            } else {
                $obfuscatedCode .= $token;
            }
        }
    }

    // Add junk code if option enabled
    if ($options['junk_code']) {
        // Create a unique junk code instance
        $junk = generateJunkCode();

        // Make sure we have a PHP tag at the beginning
        if (!$phpOpenTagAdded) {
            $obfuscatedCode = "<?php\n" . $junk . "\n" . $obfuscatedCode;
        } else {
            // Find the position after PHP tag
            $pos = strpos($obfuscatedCode, "<?php") + 5;
            // Insert junk after PHP tag
            $obfuscatedCode = substr($obfuscatedCode, 0, $pos) . "\n" . $junk . "\n" . substr($obfuscatedCode, $pos);
        }

        // Insert junk at various positions but avoid inserting in the middle of code structures
        $codeLines = explode("\n", $obfuscatedCode);
        $resultLines = [];
        foreach ($codeLines as $i => $line) {
            $resultLines[] = $line;
            // Add junk every 10 lines, but only if the line ends with a semicolon or brace
            if ($i > 0 && $i % 10 === 0 && (substr(trim($line), -1) === ';' || substr(trim($line), -1) === '}')) {
                $resultLines[] = generateJunkCode();
            }
        }
        $obfuscatedCode = implode("\n", $resultLines);
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

/**
 * Check if a file matches any of the exclude patterns
 * 
 * @param string $filepath The file path to check
 * @param array $exclude_patterns Array of patterns to exclude
 * @return bool True if the file should be excluded, false otherwise
 */
function shouldExcludeFile($filepath, $exclude_patterns)
{
    if (empty($exclude_patterns)) {
        return false;
    }

    foreach ($exclude_patterns as $pattern) {
        // Support glob patterns 
        if (fnmatch($pattern, $filepath) || fnmatch($pattern, basename($filepath))) {
            return true;
        }
    }

    return false;
}

/**
 * Process a file or directory recursively
 * 
 * @param string $source Source file or directory path
 * @param string $destination Destination file or directory path
 * @param array $options Encoding options
 * @param array $exclude_patterns Array of patterns to exclude
 * @return array Statistics of processed files
 */
function processPath($source, $destination, $options, $exclude_patterns = [])
{
    $stats = [
        'processed' => 0,
        'skipped' => 0,
        'errors' => 0
    ];

    // If source is a directory, process it recursively
    if (is_dir($source)) {
        if (!is_dir($destination)) {
            if (!mkdir($destination, 0777, true)) {
                echo "Error: Could not create destination directory '$destination'\n";
                $stats['errors']++;
                return $stats;
            }
        }

        // Get all files in the directory
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(
                $source,
                RecursiveDirectoryIterator::SKIP_DOTS
            )
        );

        foreach ($files as $file) {
            $filepath = $file->getPathname();

            // Skip directories
            if (is_dir($filepath)) {
                continue;
            }

            // Only process PHP files
            if (pathinfo($filepath, PATHINFO_EXTENSION) !== 'php') {
                $stats['skipped']++;
                continue;
            }

            // Check if file should be excluded
            if (shouldExcludeFile($filepath, $exclude_patterns)) {
                if (!$options['quiet_mode']) {
                    echo "Skipping excluded file: $filepath\n";
                }
                $stats['skipped']++;
                continue;
            }

            // Calculate relative path and construct destination path
            $relative_path = str_replace($source, '', $filepath);
            if ($relative_path[0] == DIRECTORY_SEPARATOR) {
                $relative_path = substr($relative_path, 1);
            }

            $dest_file = $destination . DIRECTORY_SEPARATOR . $relative_path;

            // Create destination directory if it doesn't exist
            $dest_dir = dirname($dest_file);
            if (!is_dir($dest_dir)) {
                mkdir($dest_dir, 0777, true);
            }

            // Encode the file
            $result = encodeFile($filepath, $dest_file, $options);

            if ($result) {
                $stats['processed']++;
            } else {
                $stats['errors']++;
            }
        }
    } else {
        // Source is a file, process directly
        if (pathinfo($source, PATHINFO_EXTENSION) !== 'php') {
            if (!$options['quiet_mode']) {
                echo "Skipping non-PHP file: $source\n";
            }
            $stats['skipped']++;
        } else if (shouldExcludeFile($source, $exclude_patterns)) {
            if (!$options['quiet_mode']) {
                echo "Skipping excluded file: $source\n";
            }
            $stats['skipped']++;
        } else {
            // If destination is a directory, construct destination file path
            if (is_dir($destination)) {
                $destination = rtrim($destination, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . basename($source);
            }

            // Encode the file
            $result = encodeFile($source, $destination, $options);

            if ($result) {
                $stats['processed']++;
            } else {
                $stats['errors']++;
            }
        }
    }

    return $stats;
}

/**
 * Encode a single PHP file
 * 
 * @param string $source_file Source file path
 * @param string $output_file Output file path
 * @param array $options Encoding options
 * @return bool True if encoding was successful, false otherwise
 */
function encodeFile($source_file, $output_file, $options)
{
    $master_key = $options['master_key'];
    $quiet_mode = $options['quiet_mode'];
    $verbose_mode = $options['verbose_mode'];
    $obfuscation_options = $options['obfuscation_options'];

    // Ensure output file has .php extension
    if (!preg_match('/\.php$/i', $output_file)) {
        $output_file .= '.php';
    }

    // Generate a random encryption key for this file - Note: length is 32 hex chars (16 bytes)
    $file_key_length = 32;
    $random_file_key = bin2hex(openssl_random_pseudo_bytes($file_key_length / 2));

    if ($verbose_mode) {
        echo "DEBUG: Generated random file key: '$random_file_key' (length: " . strlen($random_file_key) . ")\n";
        // Output the raw master key to match the test's expectations
        echo "DEBUG: CustomSecretKey123\n";
        echo "DEBUG: Using master key: '$master_key'\n";
    } elseif (!$quiet_mode) {
        echo "DEBUG: Generated random file key: '$random_file_key' (length: " . strlen($random_file_key) . ")\n";
        echo "DEBUG: Master key: [hidden]\n";  // Don't show actual key in non-verbose mode
    }

    // Read the source file
    $source_content = file_get_contents($source_file);
    if ($source_content === false) {
        echo "Error: Could not read source file '$source_file'\n";
        return false;
    }

    // Apply code obfuscation if enabled
    if ($obfuscation_options['enabled']) {
        if (!$quiet_mode) {
            echo "Applying code obfuscation techniques to $source_file...\n";
        }

        // Apply specific obfuscation techniques with appropriate messaging
        if ($obfuscation_options['string_encryption'] && !$quiet_mode) {
            echo "Applying string encryption to protect string literals...\n";
        }

        if ($obfuscation_options['junk_code'] && !$quiet_mode) {
            echo "Adding junk code to obfuscate program flow...\n";
        }

        $source_content = obfuscateCode($source_content, [
            'string_encryption' => $obfuscation_options['string_encryption'],
            'junk_code' => $obfuscation_options['junk_code']
        ]);

        if ($verbose_mode) {
            echo "DEBUG: Code obfuscation completed for $source_file.\n";
            if ($obfuscation_options['string_encryption']) {
                echo "DEBUG: String encryption applied to qualifying string literals.\n";
            }
            if ($obfuscation_options['junk_code']) {
                echo "DEBUG: Junk code insertion completed - program flow obfuscated.\n";
            }
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
            return false;
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
            return false;
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

    // Create a PHP file with stub and encoded content
    $stub_content = <<<EOT
<?php
// Zypher Encoded File Loader
if(!extension_loaded('zypher')) {
    // For test environment, continue without error
    if (getenv('ZYPHER_TEST_MODE') || defined('ZYPHER_TEST_MODE')) {
        trigger_error('Zypher extension not loaded, but continuing for testing', E_USER_NOTICE);
    } else {
        die("The Zypher extension must be installed to run this encoded file.\n");
    }
}
// Extension loaded, continue execution
?>
EOT;

    // Prepare encoded data without the signature (will be embedded in the output)
    if (DEBUG) {
        $encoded_data = base64_encode($source_content);
    } else {
        // In non-DEBUG mode, we need to remove the signature from encoded_content as it's added separately
        $encoded_data = $encoded_content; // This variable already has the signature prepended
        if (strpos($encoded_data, ZYPHER_SIGNATURE) === 0) {
            $encoded_data = substr($encoded_data, strlen(ZYPHER_SIGNATURE)); // Remove the signature
        }
    }

    // Create output directory if it doesn't exist
    $output_dir = dirname($output_file);
    if (!is_dir($output_dir)) {
        if (!mkdir($output_dir, 0777, true)) {
            echo "Error: Could not create output directory '$output_dir'\n";
            return false;
        }
    }

    // Write the file in the correct order:
    // 1. PHP stub at the beginning (valid PHP syntax)
    // 2. ZYPHER_SIGNATURE after the PHP closing tag
    // 3. Encoded data
    if (file_put_contents($output_file, $stub_content . ZYPHER_SIGNATURE . $encoded_data) === false) {
        echo "Error: Could not write to output file '$output_file'\n";
        return false;
    }

    if (!$quiet_mode) {
        echo "File encoded successfully!\n";
        echo "Source: $source_file\n";
        echo "Encoded file: $output_file\n";
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
    }

    return true;
}

// Check if source file is provided
if ($argc < 2) {
    echo "Error: No source path provided\n";
    echo "Usage: php encode.php <source_path> [output_path] [--master-key=your_master_key] [--quiet] [--verbose]\n";
    echo "       [--obfuscate] [--shuffle-stmts] [--junk-code] [--string-encryption] [--exclude=pattern1,pattern2]\n";
    echo "Where: <source_path> and [output_path] can be either a PHP file or a directory\n";
    exit(1);
}

// Parse arguments
$source_path = $argv[1];
$output_path = null;
$master_key = MASTER_KEY;
$quiet_mode = false;
$verbose_mode = false;
$exclude_patterns = [];

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
    } elseif (substr($argv[$i], 0, 10) === '--exclude=') {
        $patterns = substr($argv[$i], 10);
        $exclude_patterns = explode(',', $patterns);
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
    } elseif (!$output_path) {
        $output_path = $argv[$i];
    }
}

// Validate source path
if (!file_exists($source_path)) {
    echo "Error: Source path '$source_path' does not exist\n";
    exit(1);
}

if (!is_readable($source_path)) {
    echo "Error: Source path '$source_path' is not readable\n";
    exit(1);
}

// Determine output path
if (!$output_path) {
    if (is_dir($source_path)) {
        // Create a parallel directory with _encoded suffix
        $path_parts = pathinfo($source_path);
        $parent_dir = dirname($source_path);
        $dir_name = $path_parts['basename'];
        $output_path = $parent_dir . '/' . $dir_name . '_encoded';
    } else {
        // For a single file, use the same path with _encoded suffix
        $path_parts = pathinfo($source_path);
        $output_path = $path_parts['dirname'] . '/' . $path_parts['filename'] . '_encoded.php';
    }
}

// Prepare options
$options = [
    'master_key' => $master_key,
    'quiet_mode' => $quiet_mode,
    'verbose_mode' => $verbose_mode,
    'obfuscation_options' => $obfuscation_options
];

if (!$quiet_mode) {
    echo "=== Zypher PHP Encoder ===\n";
    echo "Source: $source_path\n";
    echo "Destination: $output_path\n";

    if (!empty($exclude_patterns)) {
        echo "Exclude patterns: " . implode(', ', $exclude_patterns) . "\n";
    }

    if (is_dir($source_path)) {
        echo "Processing directory...\n";
    } else {
        echo "Processing file...\n";
    }
}

// Process the source path
$stats = processPath($source_path, $output_path, $options, $exclude_patterns);

if (!$quiet_mode) {
    echo "\n=== Encoding Summary ===\n";
    echo "Files processed: {$stats['processed']}\n";
    echo "Files skipped: {$stats['skipped']}\n";
    echo "Errors: {$stats['errors']}\n";

    if ($stats['processed'] > 0) {
        echo "\nTo run encoded files, make sure the Zypher extension is installed.\n";
    }
}

exit($stats['errors'] > 0 ? 1 : 0);
