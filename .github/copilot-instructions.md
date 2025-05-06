# Zypher Encoder/Loader Copilot Instructions

## Project Context

This is a PHP source code protection system called Zypher, similar to ionCube. It consists of:

1. **Encoder**: A C binary that compiles PHP to opcodes, encrypts them with AES-256, and stores them in `.php` files
2. **Loader**: A PHP extension (Zend Engine) that decrypts and executes the encoded files at runtime

The system works by:
- Converting PHP source to opcodes using Zend APIs
- Encrypting the opcodes with a master key generated at build time
- Creating PHP files with encrypted content that can only be executed with the loader extension

## System Structure

```
zypher/
├── build/               # Build artifacts and generated key (zypher_master_key.h)
├── encoder/             # Encoder source files (main.c, encoder.c)
├── include/             # Common header files for both encoder and loader
├── loader/              # PHP extension loader implementation
│   ├── include/         # Loader-specific headers
│   └── modules/         # Compiled extension modules
├── tests/               # Test files and scripts
├── Makefile             # Build configuration
└── README.md            # Project documentation
```

## Key Components

1. **Master Key**: Generated during `make` in `build/zypher_master_key.h`
2. **Encryption**: AES-256-CBC with derived keys based on filenames
3. **File Format**: Encoded files have a signature marker (`ZYPHER:`) followed by base64 encrypted content

## Encoder Process Flow

1. Parse source PHP file
2. Compile to opcodes using `zend_compile_file()`
3. Serialize opcodes
4. Generate a file-specific key derived from the master key
5. Encrypt serialized opcodes
6. Store in output file with PHP stub

## Loader Process Flow

1. Hook `zend_compile_file()` to intercept PHP file loads
2. Detect Zypher signature in file
3. Extract encrypted content and metadata
4. Decrypt using master key
5. Deserialize opcodes
6. Execute using Zend VM

## Security Features

- AES-256 encryption
- File-specific derived keys
- Anti-debugging measures
- Domain and timestamp-based licensing
- Byte rotation for additional obfuscation
- Checksum verification

## Implementation Details

- The master key is embedded in both the encoder and loader at compile time
- Key derivation uses HMAC-SHA256 with multiple iterations
- File checksums ensure tamper protection
- Code runs in PHP 7.2+ and 8.x environments
- OpenSSL library is used for cryptographic operations

## Code Style and Patterns

- Error handling uses return codes throughout
- Memory management follows proper allocation/freeing patterns
- Zend API is used for PHP integration
- Debug utilities are conditionally compiled based on build flags

## Common Tasks

- **Adding features**: Modify both encoder.c and its corresponding loader implementation
- **Security fixes**: Update both encryption and decryption methods
- **PHP compatibility**: Test with target PHP versions
- **Performance tuning**: Review opcode handling and decryption process

## Testing

Test files are in `/tests` directory:
- `basic.php`: Simple class implementation to verify encoding works
- `advanced.php`: Tests namespaces, typed properties, and complex functionality
- `run.sh`: Automated test script that compares original vs encoded outputs

## Makefile Targets

- `make`: Builds everything
- `make encoder`: Builds only the encoder binary
- `make loader`: Builds the PHP extension
- `make debug_loader`: Builds a version with debug output
- `make install`: Installs the extension
- `make test`: Runs basic tests