# Zypher - PHP Encryption and Licensing System

## Overview

Zypher is a PHP source code encryption system that protects your PHP code with AES-256-CBC encryption and provides licensing functionality to control access to your software.

## Features

- **AES-256-CBC Encryption**: Strong encryption to protect your PHP source code
- **PHP Extension**: Fast C-based decryption at runtime
- **Simple Implementation**: Easy to use and integrate with existing PHP projects
- **Customizable**: Configure encryption keys and licensing parameters
- **Standard PHP Extension**: Encoded files maintain the standard `.php` extension

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

```bash
cd /path/to/zypher
php encoder/encode.php your_script.php [output_file.php] [--key=YourSecretKey]
```

If you don't specify an output file, the encoder will use the input filename with `_encoded.php` extension.

### Running encoded files

Simply run the encoded file with PHP as you would any PHP script:

```bash
php your_script_encoded.php
```

If the Zypher extension is not installed, users will see an error message prompting them to install it.

## How It Works

Encoded files are standard PHP files with a special structure:
1. They begin with a PHP stub that displays an error message for users without the Zypher extension
2. The actual encoded content follows the stub, marked with a signature
3. When executed on a system with Zypher installed, the content is automatically decoded and executed

## Security Considerations

- Keep your encryption key secure and different from the default
- Regularly update your encryption keys
- Consider using different keys for different customers

## Troubleshooting

- **Bus Error/Segmentation Fault**: Check PHP compatibility and memory allocation
- **Decoding Failed**: Ensure encryption keys match between encoding and decoding

## License

This software is proprietary and confidential.
Copyright © 2025. All rights reserved.