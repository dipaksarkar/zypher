# Zypher Loader - PHP Extension

The Zypher Loader is a PHP extension that allows execution of PHP files encrypted with the Zypher Encoder. It provides runtime decryption of protected source code while maintaining high performance.

## Features

- **Secure Runtime Decryption**: AES-256-CBC decryption of encoded PHP files
- **Signature Verification**: Validates encrypted files by checking for the Zypher signature
- **Binary Format Support**: Handles custom binary format with proper versioning
- **String Decryption**: Provides `zypher_decode_string()` function for obfuscated string literals
- **Obfuscation Support**: Compatible with various code transformation techniques:
  - String encryption/obfuscation
  - Junk code insertion
  - Statement shuffling
- **Performance Optimized**: Uses efficient C implementation for minimal performance impact
- **Memory Safety**: Carefully manages memory to prevent leaks
- **Error Handling**: Graceful failure with meaningful error messages
- **PHP Version Support**: Compatible with PHP 7.2 and higher

## Requirements

- PHP 7.2+ (development headers required for building)
- OpenSSL library and development headers
- C compiler (GCC, Clang, etc.)
- Autotools (autoconf, automake, libtool)

## Building from Source

### Prerequisites

Make sure you have the required development tools and libraries:

```bash
# For Debian/Ubuntu
sudo apt-get install php-dev libssl-dev build-essential autoconf

# For CentOS/RHEL
sudo yum install php-devel openssl-devel gcc make autoconf

# For macOS (using Homebrew)
brew install autoconf automake libtool openssl
```

### Compilation Steps

1. **Configure the build:**

```bash
cd /path/to/zypher/loader
phpize
./configure --with-openssl=/path/to/openssl
```

2. **Build the extension:**

```bash
make
```

3. **Install the extension:**

```bash
sudo make install
```

The installation process (`make install`) will:
- Install the extension binary (`zypher.so`) into your PHP extensions directory
- Create configuration files that automatically load the extension as a Zend extension
- Add `00-zypher.ini` files to both CLI and PHP-FPM configuration directories (if applicable)

> **IMPORTANT**: Zypher must be loaded as a `zend_extension` rather than a regular `extension` for proper code decryption. The installation process handles this automatically.

### Verifying Installation

Check if the extension is correctly loaded:

```bash
php -m | grep zypher
```

Or check using PHP:

```php
<?php
if (extension_loaded('zypher')) {
    echo "Zypher extension loaded successfully!\n";
} else {
    echo "Zypher extension not loaded!\n";
}
```

## Testing

The extension comes with a comprehensive test suite using PHP's PHPT test format.

### Running Tests

```bash
cd /path/to/zypher/loader
make test
```

Or for more detailed test output:

```bash
cd /path/to/zypher/loader
php run-tests.php tests/
```

### Test Coverage

The test suite covers:

- Extension loading and initialization
- File signature detection
- Base64 decoding functionality
- Decryption of encoded PHP files
- String encryption/decryption
- Various obfuscation techniques
- Error handling and edge cases

## Integration with Zypher Encoder

This loader extension works in tandem with the Zypher Encoder to create a complete PHP code protection system:

1. Encode your PHP files using the Zypher Encoder
2. Deploy the encoded files to your production server
3. Install this Zypher Loader extension on the server
4. Run your application normally - protected files will be automatically decrypted at runtime

## Security Notes

- Keep your master keys secure and never expose them
- The extension should be compiled with optimizations enabled in production
- Regularly update both the encoder and loader to get security fixes

## Troubleshooting

- **Encoded files fail to execute**: Ensure the loader extension is properly installed and the same master key was used for encoding
- **Performance issues**: Check for memory leaks or enable OpCache to improve performance
- **Compilation errors**: Make sure you have the correct development headers installed

## Internal Architecture

The loader consists of several components:

- **Main**: Extension initialization and PHP integration (`main.c`)
- **Decrypt**: Core decryption and file processing logic (`decrypt.c`)
- **Security**: Security-related functions and validation (`security.c`)
- **Utils**: Helper functions for low-level operations (`utils.c`)

## License

Proprietary - All rights reserved