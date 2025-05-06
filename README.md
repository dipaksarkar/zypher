# Zypher PHP Encoder

Zypher is a comprehensive PHP source code protection system that encrypts PHP files using AES-256-CBC encryption. It consists of two main components:

1. **PHP Encoder**: A Composer-based PHP application that encrypts PHP source code
2. **PHP Extension (Loader)**: A C-based extension that decrypts and executes protected PHP files at runtime

## Features

- **Strong Encryption**: Uses AES-256-CBC with file-specific key derivation
- **Code Obfuscation**: Multiple techniques including:
  - Variable name obfuscation
  - String encryption
  - Junk code insertion
  - Statement shuffling
- **Flexible Options**: Configurable encryption strength and obfuscation levels
- **Composer Integration**: Modern PHP project structure with PSR-4 autoloading
- **Command-line Interface**: Easy-to-use CLI tool
- **Cross-platform**: Works on Linux, macOS, and Windows

## Requirements

- PHP 7.2 or higher
- OpenSSL extension
- Composer

## Installation

### Via Composer

```bash
composer require zypher/encoder
```

### Manual Installation

```bash
git clone https://github.com/zypher/encoder.git
cd encoder
composer install
```

## Usage

### Basic Usage

```bash
./bin/zypher /path/to/source.php /path/to/output.php
```

### Directory Encoding

```bash
./bin/zypher /path/to/source/dir /path/to/output/dir
```

### With Custom Master Key

```bash
./bin/zypher /path/to/source.php /path/to/output.php --master-key=your_secure_key
```

### With Obfuscation Options

```bash
./bin/zypher /path/to/source.php /path/to/output.php --obfuscate --string-encryption --junk-code
```

### Exclude Files

```bash
./bin/zypher /path/to/source/dir /path/to/output/dir --exclude=vendor/*,tests/*
```

### Quiet or Verbose Mode

```bash
./bin/zypher /path/to/source.php /path/to/output.php --quiet
./bin/zypher /path/to/source.php /path/to/output.php --verbose
```

## Command-line Options

| Option | Description |
|--------|-------------|
| `--master-key=KEY` | Set encryption master key (strongly recommended) |
| `--obfuscate` | Enable code obfuscation |
| `--string-encryption` | Enable string literal encryption |
| `--junk-code` | Insert junk code to confuse reverse-engineering attempts |
| `--shuffle-stmts` | Shuffle statement order where possible |
| `--exclude=PATTERN` | Exclude files matching pattern (comma-separated) |
| `--quiet` | Suppress non-error output |
| `--verbose` | Show detailed encoding information |

## Extension Installation

To run encoded files, you need to install the Zypher Loader extension.

For detailed instructions on building and installing the extension, please see the [Zypher Loader README](loader/README.md).

Quick installation:

```bash
cd loader
phpize
./configure
make
sudo make install
```

The installation process automatically configures PHP to load the extension, no manual editing of php.ini is required.

> **IMPORTANT**: Zypher is loaded as a `zend_extension` rather than a regular `extension` for proper code decryption.

## Testing

The project includes a comprehensive test suite covering various aspects of the Zypher encoder functionality.

### Test Suites

- **Stubs Tests**: Tests encoding with different options using stub PHP files
- **Integration Tests**: Tests that validate end-to-end functionality with the PHP extension
- **Error Handling Tests**: Tests for proper handling of edge cases and error conditions

### Running Tests

Run all tests:

```bash
vendor/bin/phpunit
```

### Integration Tests

Integration tests verify that encoded files can be properly executed by the Zypher loader extension. These tests:

1. Encode PHP files with various options
2. Execute both the original and encoded versions
3. Compare the results to ensure identical behavior

Note: Integration tests are automatically skipped if the Zypher extension is not loaded in PHP.

### Testing with the Extension

To run integration tests, you need to have the Zypher extension installed. Please refer to the [Extension Installation](#extension-installation) section above for installation instructions.

## Security Recommendations

1. **Always use a custom master key** in production
2. **Keep your master key secure** - never commit it to version control
3. **Use all obfuscation options** for maximum security
4. **Regularly update** both the encoder and loader components

## Project Structure

- **bin/**: Command-line tools
- **src/**: Source code for the encoder
- **loader/**: PHP extension source code
- **tests/**: Unit and integration tests

## To-Do
- [ ] Adding additional test cases to ensure robustness
- [ ] Improving the documentation in code comments
- [ ] Enhancing any of the obfuscation features
- [ ] Implementing additional security measures

## License

Proprietary - All rights reserved.

## Support

For questions and support, please open an issue on the GitHub repository or contact support@zypher.com.