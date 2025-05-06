# Zypher - PHP Encoder and Loader System

Zypher is a comprehensive PHP source code protection system that encodes PHP files into an encrypted format that can only be executed with the companion Zypher loader extension.

## Features

- **Strong Encryption**: Uses industry-standard AES-256 encryption to protect source code
- **Opcode Caching**: Pre-compiles PHP code for improved performance
- **License Management**: Lock encoded files to specific domains or expiration dates
- **Anti-Debugging**: Prevents use of debugging tools to reverse engineer code
- **Compatibility**: Works with PHP 7.x and 8.x

## System Requirements

- PHP 7.2 or newer (compatible with PHP 8.x)
- OpenSSL library
- C compiler (GCC/Clang)
- PHP development headers (php-dev package)

## Directory Structure

```
zypher/
├── build/               # Build artifacts and generated keys
├── encoder/             # Encoder source files
├── include/             # Common header files
├── loader/              # PHP extension loader
│   ├── build/           # Build files for PHP extension
│   ├── include/         # Loader-specific headers
│   └── modules/         # Compiled extension modules
├── tests/               # Test files and scripts
├── Makefile             # Build configuration
└── README.md            # This file
```

## Building the Zypher System

To build the entire Zypher system (both encoder and loader), run:

```bash
make
```

This will:
1. Create necessary directories
2. Generate a master encryption key
3. Build the encoder binary
4. Build the PHP extension loader

### Building Individual Components

To build only the encoder:

```bash
make encoder
```

To build only the loader:

```bash
make loader
```

To build a debug version of the loader with additional diagnostics:

```bash
make debug_loader
```

## Installation

After building, you can install the PHP extension to your PHP installation:

```bash
make install
```

Then add the following line to your php.ini:

```
extension=zypher.so
```

## Using the Encoder

The encoder is a command-line tool used to encode PHP files:

```bash
./zypher [options] input_file [output_file]
```

### Options:

- `-o <file>` - Specify output file (alternative to providing as second parameter)
- `-b` - Enable obfuscation for encoded files
- `-e <date>` - Set expiration date (format: YYYY-MM-DD)
- `-l <domain>` - Lock to a specific domain
- `-v` - Enable verbose output
- `-h` - Display help

### Examples:

```bash
# Basic encoding
./zypher script.php

# Specify output file
./zypher -o script.encoded.php script.php

# Encode with expiration date
./zypher -e 2025-12-31 script.php

# Encode with domain lock
./zypher -l example.com script.php

# Encode with obfuscation enabled
./zypher -b script.php
```

## Testing

To verify that your Zypher installation is working correctly, run:

```bash
make test
```

For more comprehensive testing:

```bash
./tests/run.sh
```

The test script will run a series of tests to verify the encoder and loader functionality, including:
- Basic functionality tests
- Advanced PHP feature tests
- Testing with different encoding options
- License verification tests

## Troubleshooting

If you encounter issues with the Zypher system, try these steps:

1. Build a debug version of the loader:
   ```bash
   make debug_loader
   ```

2. Run your encoded file with the debug loader:
   ```bash
   php -d extension=/path/to/zypher_debug.so your_encoded_file.php
   ```

3. Check your system information:
   ```bash
   make info
   ```

## Security Notes

- The master encryption key (`zypher_master_key.h`) is essential for security. Keep this file secure and private.
- Do not share the encoder binary with end users - only distribute the loader extension.
- For maximum security, encode files on a secure, isolated system.

## License

© 2025 Zypher Team. All rights reserved.

---

For technical assistance or questions, please contact support@zypher.example.com