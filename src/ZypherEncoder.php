<?php

namespace Zypher;

/**
 * ZypherEncoder class
 * 
 * Main encoder class that handles file encryption and processing
 * 
 * @package Zypher
 */

/**
 * Main encoder class
 */
class ZypherEncoder
{
    /**
     * @var EncoderOptions
     */
    private $options;

    /**
     * @var Obfuscator
     */
    private $obfuscator;

    /**
     * @var OpcodeCompiler
     */
    private $opcodeCompiler;

    /**
     * @var array Statistics of processing
     */
    private $stats = [
        'processed' => 0,
        'skipped' => 0,
        'errors' => 0
    ];

    /**
     * Constructor
     * 
     * @param EncoderOptions $options
     */
    public function __construct(EncoderOptions $options)
    {
        $this->options = $options;

        // If no custom master key was provided, use the one from environment variables
        if (empty($this->options->masterKey)) {
            $this->options->masterKey = Constants::getMasterKey();
        }

        $this->obfuscator = new Obfuscator();
        $this->opcodeCompiler = new OpcodeCompiler($options->verboseMode);
    }

    /**
     * Enhanced key derivation function using HMAC-SHA256 with multiple iterations
     * 
     * @param string $masterKey The master key 
     * @param string $filename The filename used to create a file-specific key
     * @param int $iterations Number of HMAC iterations for key strengthening
     * @return string The derived key as a hexadecimal string
     */
    public function deriveFileKey($masterKey, $filename, $iterations = 1000)
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
     * Check if a file matches any of the exclude patterns
     * 
     * @param string $filepath The file path to check
     * @param array $exclude_patterns Array of patterns to exclude
     * @return bool True if the file should be excluded, false otherwise
     */
    public function shouldExcludeFile($filepath, $exclude_patterns)
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
     * @return array Statistics of processed files
     */
    public function processPath($source, $destination)
    {
        // If source is a directory, process it recursively
        if (is_dir($source)) {
            if (!is_dir($destination)) {
                if (!mkdir($destination, 0777, true)) {
                    echo "Error: Could not create destination directory '$destination'\n";
                    $this->stats['errors']++;
                    return $this->stats;
                }
            }

            // Get all files in the directory
            $files = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator(
                    $source,
                    \RecursiveDirectoryIterator::SKIP_DOTS
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
                    $this->stats['skipped']++;
                    continue;
                }

                // Check if file should be excluded
                if ($this->shouldExcludeFile($filepath, $this->options->excludePatterns)) {
                    if ($this->options->verboseMode) {
                        echo "Skipping excluded file: $filepath\n";
                    }
                    $this->stats['skipped']++;
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
                $result = $this->encodeFile($filepath, $dest_file);

                if ($result) {
                    $this->stats['processed']++;
                } else {
                    $this->stats['errors']++;
                }
            }
        } else {
            // Source is a file, process directly
            if (pathinfo($source, PATHINFO_EXTENSION) !== 'php') {
                if ($this->options->verboseMode) {
                    echo "Skipping non-PHP file: $source\n";
                }
                $this->stats['skipped']++;
            } else if ($this->shouldExcludeFile($source, $this->options->excludePatterns)) {
                if ($this->options->verboseMode) {
                    echo "Skipping excluded file: $source\n";
                }
                $this->stats['skipped']++;
            } else {
                // If destination is a directory, construct destination file path
                if (is_dir($destination)) {
                    $destination = rtrim($destination, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . basename($source);
                }

                // Encode the file
                $result = $this->encodeFile($source, $destination);

                if ($result) {
                    $this->stats['processed']++;
                } else {
                    $this->stats['errors']++;
                }
            }
        }

        return $this->stats;
    }

    /**
     * Encode a single PHP file
     * 
     * @param string $source_file Source file path
     * @param string $output_file Output file path
     * @return bool True if encoding was successful, false otherwise
     */
    public function encodeFile($source_file, $output_file)
    {
        // Ensure output file has .php extension
        if (!preg_match('/\.php$/i', $output_file)) {
            $output_file .= '.php';
        }

        // Generate a random encryption key for this file - Note: length is 32 hex chars (16 bytes)
        $file_key_length = 32;
        $random_file_key = bin2hex(openssl_random_pseudo_bytes($file_key_length / 2));

        if ($this->options->verboseMode) {
            echo "DEBUG: Generated random file key: '$random_file_key' (length: " . strlen($random_file_key) . ")\n";
            // Don't output the actual master key in logs - security risk
            echo "DEBUG: Using master key hash: '" . md5($this->options->masterKey) . "' (showing hash only)\n";
        }

        // Read the source file
        $source_content = file_get_contents($source_file);
        if ($source_content === false) {
            echo "Error: Could not read source file '$source_file'\n";
            return false;
        }

        // Apply code obfuscation if enabled
        if ($this->options->obfuscation['enabled']) {
            echo "Applying code obfuscation techniques to $source_file...\n";

            // Apply specific obfuscation techniques with appropriate messaging
            if ($this->options->obfuscation['string_encryption'] && $this->options->verboseMode) {
                echo "Applying string encryption to protect string literals...\n";
            }

            if ($this->options->obfuscation['junk_code'] && $this->options->verboseMode) {
                echo "Adding junk code to obfuscate program flow...\n";
            }

            $source_content = $this->obfuscator->obfuscateCode($source_content, [
                'string_encryption' => $this->options->obfuscation['string_encryption'],
                'junk_code' => $this->options->obfuscation['junk_code']
            ]);

            // Create a backup if in verbose mode
            if ($this->options->verboseMode) {
                file_put_contents($source_file . '.bak', $source_content);
                echo "DEBUG: Created backup of obfuscated source at {$source_file}.bak\n";
            }

            if ($this->options->verboseMode) {
                echo "DEBUG: Code obfuscation completed for $source_file.\n";
                if ($this->options->obfuscation['string_encryption']) {
                    echo "DEBUG: String encryption applied to qualifying string literals.\n";
                }
                if ($this->options->obfuscation['junk_code']) {
                    echo "DEBUG: Junk code insertion completed - program flow obfuscated.\n";
                }
            }
        }

        // Always use proper AES encryption
        // Generate random IVs for both content and key encryption
        $content_iv = openssl_random_pseudo_bytes(16); // IV for content encryption
        $key_iv = openssl_random_pseudo_bytes(16);     // IV for key encryption

        if ($this->options->verboseMode) {
            echo "DEBUG: Using AES-256-CBC encryption\n";
            echo "DEBUG: Content IV (hex): " . bin2hex($content_iv) . " (length: " . strlen($content_iv) . ")\n";
            echo "DEBUG: Key IV (hex): " . bin2hex($key_iv) . " (length: " . strlen($key_iv) . ")\n";
        }

        // Using the base filename for key derivation is critical!
        $base_filename = basename($source_file);

        // Add a timing protection factor - use an expensive key derivation
        $start_time = microtime(true);

        // Derive a file-specific key from master key and filename
        $derived_master_key = $this->deriveFileKey($this->options->masterKey, $base_filename, 1000); // Increased iterations

        $end_time = microtime(true);
        if ($this->options->verboseMode) {
            echo "DEBUG: Key derivation took " . round(($end_time - $start_time) * 1000, 2) . " ms\n";
            echo "DEBUG: Using base filename '$base_filename' for key derivation\n";
            echo "DEBUG: Derived master key: $derived_master_key (length: " . strlen($derived_master_key) . ")\n";
        }

        // Prepare content for encryption
        $content_to_encrypt = '';
        $format_type = $this->options->opcodes['format_type'];

        if ($this->options->opcodes['enabled']) {
            echo "Compiling PHP to opcodes for $source_file...\n";
            // Compile PHP to opcodes before encryption
            $opcodes = $this->opcodeCompiler->compileToOpcodes($source_content, $base_filename);

            if (!$opcodes) {
                echo "Error: Failed to compile PHP to opcodes. Falling back to source code.\n";
                // Fallback to source code
                $content_to_encrypt = $source_content;
                $format_type = Constants::FORMAT_SOURCE;
            } else {
                $content_to_encrypt = $opcodes;
                echo "Successfully compiled to opcodes.\n";

                if ($this->options->verboseMode) {
                    echo "DEBUG: Opcode size: " . strlen($content_to_encrypt) . " bytes\n";
                }
            }
        } else {
            // Use source code directly
            $content_to_encrypt = $source_content;
            $format_type = Constants::FORMAT_SOURCE;
        }

        // Add checksum for integrity checking - helps detect tampering
        $checksum = md5($content_to_encrypt);

        // Integrity: Add timestamp to prevent replay attacks if that were a concern
        $timestamp = time();
        $timestamp_bytes = pack("N", $timestamp);

        // Add version and format type markers for future compatibility
        $version = $this->options->opcodes['format_version'];
        $version_byte = chr($version);
        $format_type_byte = chr($format_type);

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

        if ($this->options->verboseMode) {
            echo "DEBUG: Random file key to encrypt: " . $random_file_key . "\n";
            echo "DEBUG: Derived master key for encryption: " . $derived_master_key . "\n";
            echo "DEBUG: Encrypted file key (hex): " . bin2hex($encrypted_file_key) . "\n";
        }

        // Now include checksum in the content to be encrypted
        $content_to_encrypt = $checksum . $content_to_encrypt;

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

        if ($this->options->verboseMode) {
            echo "DEBUG: Encrypted file key length: " . strlen($encrypted_file_key) . " bytes\n";
            echo "DEBUG: Encrypted content size: " . strlen($encrypted_content) . " bytes\n";
        }

        // Enhanced Format:
        // - 1 byte: version marker
        // - 1 byte: format type (1 = source, 2 = opcode)
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

        if ($this->options->verboseMode) {
            echo "DEBUG: Including original filename '$orig_filename' (length: $filename_length) for key derivation\n";
            echo "DEBUG: Format version: $version\n";
            echo "DEBUG: Format type: $format_type (" . ($format_type == Constants::FORMAT_OPCODE ? "opcode" : "source") . ")\n";
            echo "DEBUG: Added timestamp: $timestamp\n";
            echo "DEBUG: Added content checksum: $checksum\n";
        }

        // Pack everything together with new format elements
        $final_content = $version_byte . $format_type_byte . $timestamp_bytes . $content_iv . $key_iv .
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
        $encoded_content = Constants::getSignature() . $encoded_content;

        // Create a PHP file with stub and encoded content
        $stub_content = <<<EOT
<?php
if(!extension_loaded('zypher')){die('The file '.__FILE__." is corrupted.\\n\\nScript error: the ".((php_sapi_name()=='cli') ?'Zypher':'<a href=\\"https://www.zypher.com\\">Zypher</a>')." Loader for PHP needs to be installed.\\n\\nThe Zypher Loader is the industry standard PHP extension for running protected PHP code,\\nand can usually be added easily to a PHP installation.\\n\\nFor Loaders please visit".((php_sapi_name()=='cli')?":\\n\\nhttps://get-loader.zypher.com\\n\\nFor":' <a href=\\"https://get-loader.zypher.com\\">get-loader.zypher.com</a> and for')." an instructional video please see".((php_sapi_name()=='cli')?":\\n\\nhttp://zypher.be/LV\\n\\n":' <a href=\\"http://zypher.be/LV\\">http://zypher.be/LV</a> ')."");}exit(0);
?>

EOT;

        // Remove signature from encoded content as it will be added separately
        $encoded_data = $encoded_content;
        if (strpos($encoded_data, Constants::getSignature()) === 0) {
            $encoded_data = substr($encoded_data, strlen(Constants::getSignature())); // Remove the signature
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
        // 2. ZYPHER_SIGNATURE after the PHP closing tag and a newline
        // 3. Encoded data
        if (file_put_contents($output_file, $stub_content . Constants::getSignature() . $encoded_data) === false) {
            echo "Error: Could not write to output file '$output_file'\n";
            return false;
        }

        echo "File encoded successfully!\n";
        echo "Source: $source_file\n";
        echo "Encoded file: $output_file\n";
        echo "Encoding type: " . ($format_type == Constants::FORMAT_OPCODE ? "PHP Opcodes" : "Source Code") . "\n";
        echo "Encryption: AES-256-CBC with secure key derivation and two-layer encryption\n";

        if ($this->options->obfuscation['enabled']) {
            echo "Applied obfuscation: ";
            $techniques = [];
            if ($this->options->obfuscation['string_encryption']) $techniques[] = "string encryption";
            if ($this->options->obfuscation['junk_code']) $techniques[] = "junk code insertion";
            if ($this->options->obfuscation['shuffle_statements']) $techniques[] = "statement shuffling";
            echo implode(", ", $techniques) . "\n";
        }

        return true;
    }

    /**
     * Get statistics of processed files
     * 
     * @return array
     */
    public function getStats()
    {
        return $this->stats;
    }
}
