# Zypher - PHP Encryption and Licensing System

## Overview

Zypher is a PHP source code encryption system that protects your PHP code with AES-256-CBC encryption and provides licensing functionality to control access to your software.

## Features

- **AES-256-CBC Encryption**: Strong encryption to protect your PHP source code
- **PHP Extension**: Fast C-based decryption at runtime
- **Simple Implementation**: Easy to use and integrate with existing PHP projects
- **Customizable**: Configure encryption keys and licensing parameters
- **Standard PHP Extension**: Encoded files maintain the standard `.php` extension
- **Code Obfuscation**: Optional code obfuscation features to further protect your code
- **String Encryption**: Encrypt string literals within the code
- **Junk Code Insertion**: Add meaningless code to confuse decompilers
- **Directory Processing**: Recursively process entire directories maintaining the folder structure
- **Exclude Patterns**: Skip files matching specified patterns during encoding

## Requirements

- PHP 7.4+ (recommended PHP 8.0+)
- OpenSSL support in PHP
- Admin access to install PHP extensions

## Installation

### 1. Build and install the extension

```bash
cd /path/to/zypher/loader
phpize
./configure
make
sudo make install
```

### 2. Configure PHP to use the extension

Add the following to your php.ini file:

```ini
extension=zypher.so
```

## Usage

### Encoding PHP files

Basic usage:

```bash
php encoder/encode.php <source_path> [output_path] [options]
```

Available options:

```
--master-key=<your_secret_key>   Use a custom encryption master key
--obfuscate                       Enable code obfuscation features
--string-encryption               Encrypt string literals in the code
--junk-code                       Insert junk code to confuse decompilers
--shuffle-stmts                   Shuffle code statements where possible
--exclude=pattern1,pattern2       Exclude files matching specified patterns
--quiet                           Suppress all output
--verbose                         Show detailed debug information
```

Examples:

```bash
# Basic encoding with default options
php encoder/encode.php your_script.php

# Specify output file
php encoder/encode.php your_script.php output.php

# Custom master key
php encoder/encode.php your_script.php --master-key=YourSecretKey123

# Enable obfuscation with all features
php encoder/encode.php your_script.php --obfuscate --string-encryption --junk-code

# Process entire directory
php encoder/encode.php /path/to/source/dir /path/to/output/dir

# Process directory excluding test files
php encoder/encode.php /path/to/source/dir --exclude=*.test.php,*_backup.php

# Process directory with multiple options
php encoder/encode.php /path/to/source/dir --exclude=vendor/*,tests/* --obfuscate
```

If you don't specify an output path:
- For a file: the encoder will use the input filename with `_encoded.php` extension.
- For a directory: the encoder will create a new directory with `_encoded` suffix.

### Running encoded files

Simply run the encoded file with PHP as you would any PHP script:

```bash
php your_script_encoded.php
```

If the Zypher extension is not installed, users will see an error message prompting them to install it.

## How It Works

Encoded files are standard PHP files with a special structure:
1. They begin with a PHP stub that displays an error message for users without the Zypher extension
2. The ZYPH01 signature marks the file as Zypher-encoded
3. The actual encoded content follows the signature
4. When executed on a system with Zypher installed, the content is automatically decoded and executed

## Security Considerations

- Keep your encryption key secure and different from the default
- Regularly update your encryption keys
- Consider using different keys for different customers
- Use the code obfuscation features for additional protection
- Combine string encryption and junk code insertion for maximum security
- Exclude sensitive configuration files that might contain credentials

## Troubleshooting

- **Bus Error/Segmentation Fault**: Check PHP compatibility and memory allocation
- **Decoding Failed**: Ensure encryption keys match between encoding and decoding
- **String Decoding Errors**: Make sure the extension has the correct string decoding function
- **Missing Files**: When encoding directories, verify your exclude patterns aren't too broad

## License

This software is proprietary and confidential.
Copyright © 2025. All rights reserved.