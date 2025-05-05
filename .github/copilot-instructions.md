# GitHub Copilot Instructions for Zypher

## Project Overview

Zypher is a PHP source code encryption and licensing system that protects PHP code with AES-256-CBC encryption. The system consists of two main components:

1. **PHP Extension (Loader)**: A C-based extension that decrypts and executes encoded PHP files at runtime
2. **PHP Encoder**: A PHP script that encrypts source code files

## Key Concepts

- **Encryption**: AES-256-CBC with derived keys for file-specific encryption
- **Signatures**: Files are marked with `ZYPH01` to identify them as Zypher-encoded
- **Obfuscation**: Several techniques including variable renaming, junk code injection, and string encryption
- **Key Derivation**: HMAC-SHA256 based derivation with iteration for file-specific keys

## Project Structure

```
/Volumes/Work/zypher/
├── .github/
│   └── copilot-instructions.md
├── encoder/
│   └── encode.php              # Main encoder script
├── loader/                     # PHP extension (C code)
│   ├── src/
│   │   ├── decrypt.c           # Decryption implementation
│   │   ├── decrypt.h           # Decryption header
│   │   ├── main.c              # Extension main entry points
│   │   ├── main.h              # Main header
│   │   ├── php_loader.h        # PHP extension integration header
│   │   ├── security.c          # Security-related functions
│   │   ├── security.h          # Security header
│   │   ├── utils.c             # Utility functions
│   │   └── utils.h             # Utilities header
│   ├── tests/                  # Extension tests
│   │   ├── 001-extension-loading.phpt
│   │   ├── 002-encoding-php-files.phpt
│   │   ├── 003-stub-code-implementation.phpt
│   │   ├── 004-php-extension-support.phpt
│   │   ├── 005-signature-detection.phpt
│   │   ├── 006-base64-decoding.phpt
│   │   ├── 007-string-encryption.phpt
│   │   ├── 008-string-decode.phpt
│   │   ├── 009-obfuscation-support.phpt
│   │   ├── 010-string-encryption-support.phpt
│   │   ├── 011-junk-code-support.phpt
│   │   ├── 012-shuffle-statements-support.phpt
│   │   └── 013-combined-obfuscation-options.phpt
│   ├── config.m4               # Build system configuration
│   ├── configure               # Generated configure script
│   ├── configure.ac            # Autoconf template
│   ├── Makefile                # Generated makefile
│   ├── Makefile.fragments      # Build fragments
│   └── run-tests.php           # Test runner script
├── tests/                      # Integration tests
│   ├── advanced_encoded.php    # Encoded version of advanced.php
│   ├── advanced.php            # Advanced test file
│   ├── encoder_comprehensive_tests.php  # Full test suite
│   ├── hello_encoded.php       # Encoded version of hello.php
│   ├── hello.php               # Basic test file
│   ├── run_tests.php           # Integration test runner
│   └── signature_detection_test.php  # Tests for signature detection
├── .gitignore
├── php.ini                     # PHP configuration
└── README.md                   # Project documentation
```

## File Roles and Key Components

### Encoder

- `encode.php`: Main encoder script that transforms PHP code into encrypted files
  - Implements AES-256-CBC encryption
  - Handles command line arguments and options
  - Manages file processing and directory traversal
  - Implements obfuscation techniques

### Loader (PHP Extension)

- `decrypt.c/h`: Handles the decryption of encoded files
- `main.c/h`: Main entry points and PHP extension integration
- `security.c/h`: Implements security features like key validation
- `utils.c/h`: Helper functions for file and string manipulation
- `php_loader.h`: PHP extension API declarations

### Tests

- `loader/tests/*.phpt`: PHPT format tests for the C extension
- `tests/*.php`: PHP-based integration tests
- `run_tests.php`: Test runners for automated testing

## Code Patterns

### Encoder Command Line Arguments

The encoder accepts the following command-line arguments pattern:

```php
php encode.php <source_path> [output_path] [--master-key=secret] [--obfuscate] [--string-encryption] [--junk-code] [--shuffle-stmts] [--exclude=pattern1,pattern2] [--quiet] [--verbose]
```

### Encoding Process

The encoding process follows this pattern:

```php
// Read source file
$source_content = file_get_contents($source_file);

// Apply obfuscation if enabled
if ($obfuscation_options['enabled']) {
    $source_content = obfuscateCode($source_content, $options);
}

// Generate random file key
$random_file_key = bin2hex(openssl_random_pseudo_bytes($length / 2));

// Derive master key from file name
$derived_key = deriveFileKey($master_key, $filename, $iterations);

// Encrypt content
$encrypted_content = openssl_encrypt($content, 'AES-256-CBC', $key, $options, $iv);

// Combine with header information
$final_content = $header . $encrypted_content;

// Add Zypher signature
$encoded_file = $stub . ZYPHER_SIGNATURE . $encoded_content;
```

### C Extension Patterns

#### Extension Registration

```c
PHP_MINIT_FUNCTION(zypher)
{
    // Initialize extension resources
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(zypher)
{
    // Clean up resources
    return SUCCESS;
}

PHP_MINFO_FUNCTION(zypher)
{
    // Display extension information
    php_info_print_table_start();
    php_info_print_table_row(2, "Zypher support", "enabled");
    php_info_print_table_row(2, "Version", PHP_ZYPHER_VERSION);
    php_info_print_table_end();
}

PHP_RINIT_FUNCTION(zypher)
{
    // Request initialization
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(zypher)
{
    // Request shutdown
    return SUCCESS;
}
```

#### File Decoding Functions

```c
static int decode_zypher_file(const char *filename, char **decoded_content, size_t *decoded_size)
{
    // 1. Read the file
    // 2. Check for Zypher signature
    // 3. Extract metadata (version, IVs, etc.)
    // 4. Derive the key
    // 5. Decrypt the content
    // 6. Return the decoded content
}
```

#### String Decryption Functions

```c
PHP_FUNCTION(zypher_decode_string)
{
    char *encoded_string;
    size_t encoded_len;
    char *key;
    size_t key_len;
    
    // Parse arguments
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &encoded_string, &encoded_len, &key, &key_len) == FAILURE) {
        RETURN_FALSE;
    }
    
    // Decrypt string
    // Return decrypted result
}
```

### PHPT Test Structure

PHPT tests follow this pattern:

```
--TEST--
Description of the test
--SKIPIF--
<?php
if (!extension_loaded('zypher')) die('skip: zypher extension not available');
?>
--FILE--
<?php
// Test code
?>
--EXPECT--
Expected output
```

### Integration Tests

```php
// Create test PHP file
$testFile = $testDir . '/test_feature.php';
$outputFile = $testDir . '/test_feature_encoded.php';

// Create test content
file_put_contents($testFile, '<?php /* test code */ ?>');

// Encode with specific options
$output = shell_exec("php $encoderPath $testFile $outputFile --option1 --option2 2>&1");

// Test verification
$verification = /* verification logic */;
```

## Common Tasks

### 1. Adding New Obfuscation Technique

When adding a new obfuscation technique:

1. Add a new command line option in the argument parsing section of `encode.php`
2. Add a new option in the `$obfuscation_options` array
3. Implement the technique in the `obfuscateCode()` function
4. Update the loader to handle the obfuscated code if necessary
5. Add appropriate tests in the test suite:
   - Unit tests in `loader/tests/`
   - Integration tests in `tests/`

### 2. Modifying Encryption Format

When modifying the encryption format:

1. Increment the version byte in the encoder (`encode.php`)
2. Update the format structure comment to reflect changes
3. Update the decryption logic in `loader/src/decrypt.c` to handle the new format
4. Ensure backward compatibility with previous versions
5. Add tests for both the new format and backward compatibility

### 3. Adding Command Line Options

When adding new command line options:

1. Add option parsing in the arguments loop in `encode.php`
2. Update the help text in the usage instructions
3. Update the README.md documentation
4. Create tests that verify the new option works correctly

### 4. Adding C Extension Functions

When adding new functions to the PHP extension:

1. Declare the function in `php_loader.h`
2. Implement the function in an appropriate C file
3. Add the function to the function entry array in `main.c`
4. Update extension documentation
5. Add tests for the new functionality

### 5. Adding Tests

When adding tests:

1. For PHP extension tests:
   - Create a new `.phpt` file in the `loader/tests/` directory
   - Follow the PHPT format (--TEST--, --SKIPIF--, --FILE--, --EXPECT--)
   
2. For integration tests:
   - Add a new test function to `tests/encoder_comprehensive_tests.php`
   - Or create a new test file in the `tests/` directory
   - Use the helper functions for file creation and verification

## Best Practices

1. **Security First**: All changes should prioritize security over convenience
2. **Backward Compatibility**: Maintain compatibility with previously encoded files
3. **Error Handling**: Provide clear error messages and fail safely
4. **Documentation**: Update comments and README when changing functionality
5. **Testing**: Every new feature or change should have corresponding tests
6. **Performance**: Consider the performance impact of cryptographic operations

## Notes

- The `DEBUG` constant in encode.php should be `false` in production
- The default master key should never be used in production
- Always verify encoded files can be decoded properly before deployment
- Consider performance implications of key derivation iterations
- When working with C code, be careful about memory management to prevent leaks
- Test the extension on multiple PHP versions to ensure compatibility
