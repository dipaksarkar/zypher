# Zypher - PHP Encryption and Licensing System

## Overview

Zypher is a PHP source code encryption system that protects your PHP code with AES-256-CBC encryption and provides licensing functionality to control access to your software.

## Features

- **AES-256-CBC Encryption**: Strong encryption to protect your PHP source code
- **PHP Extension**: Fast C-based decryption at runtime
- **License Management**: Control access based on expiration dates and features
- **Simple Implementation**: Easy to use and integrate with existing PHP projects
- **Customizable**: Configure encryption keys and licensing parameters

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
zypher.encryption_key=YourSecretKey
zypher.license_path=/path/to/license.key
zypher.license_check_enabled=1
```

## Usage

### Encoding PHP files

```bash
cd /path/to/zypher
php encoder/encode.php your_script.php [output_file.penc] [--key=YourSecretKey]
```

If you don't specify an output file, the encoder will use the input filename with `.penc` extension.

### Running encoded files

Simply run the encoded file with PHP as you would any PHP script:

```bash
php your_script.penc
```

### License File Format

Create a license file with the following format:

```
License-Key: ZYPHER-XXXX-XXXX-XXXX-XXXX
Customer: Customer Name
Expires: YYYY-MM-DD
Type: Enterprise|Standard|Basic
Features: Feature1,Feature2,Feature3
```

## Security Considerations

- Keep your encryption key secure and different from the default
- Use a secure method to distribute license files
- Regularly update your encryption keys
- Consider using different keys for different customers

## Troubleshooting

- **Bus Error/Segmentation Fault**: Check PHP compatibility and memory allocation
- **Decoding Failed**: Ensure encryption keys match between encoding and decoding
- **License Invalid**: Verify license file format and expiration dates

## License

This software is proprietary and confidential.
Copyright © 2025. All rights reserved.