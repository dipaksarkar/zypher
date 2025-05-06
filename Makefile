# Makefile for Zypher PHP Encoder/Loader System
# Author: Zypher Team
# Date: May 7, 2025

# Directories
ROOT_DIR := $(shell pwd)
BUILD_DIR := $(ROOT_DIR)/build
ENCODER_DIR := $(ROOT_DIR)/encoder
LOADER_DIR := $(ROOT_DIR)/loader
INCLUDE_DIR := $(ROOT_DIR)/include
TEST_DIR := $(ROOT_DIR)/tests

# Commands and tools
CC := gcc
PHP_CONFIG := php-config
OPENSSL := openssl
PHP := php
PHPIZE := phpize

# PHP version and binary info
PHP_VERSION := $(shell $(PHP_CONFIG) --version | cut -d. -f1,2)
PHP_BINARY := $(shell which $(PHP))
PHP_EXTENSION_DIR := $(shell $(PHP_CONFIG) --extension-dir)

# Compiler flags
CFLAGS := -Wall -O2 -fPIC -I$(INCLUDE_DIR)
LDFLAGS := -lssl -lcrypto

# Master key file
MASTER_KEY_FILE := $(BUILD_DIR)/zypher_master_key.h

# Output files
ENCODER_BIN := $(ROOT_DIR)/zypher
LOADER_SO := $(LOADER_DIR)/modules/zypher.so

# Encoder source files
ENCODER_SOURCES := $(ENCODER_DIR)/main.c \
                  $(ENCODER_DIR)/encoder.c \
                  $(ENCODER_DIR)/encoder_crypto.c \
                  $(ENCODER_DIR)/encoder_opcode.c \
                  $(ENCODER_DIR)/encoder_utils.c

# Default target
all: directories master_key encoder loader

# Create necessary directories with proper permissions
directories:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(TEST_DIR)
	@mkdir -p $(LOADER_DIR)/modules
	@mkdir -p $(LOADER_DIR)/build
	@chmod -R 755 $(BUILD_DIR) $(LOADER_DIR)/build $(LOADER_DIR)/modules

# Generate the master encryption key if it doesn't exist
master_key: $(MASTER_KEY_FILE)

$(MASTER_KEY_FILE):
	@echo "Generating secure master encryption key..."
	@mkdir -p $(BUILD_DIR)
	@echo "#ifndef ZYPHER_MASTER_KEY_H" > $(MASTER_KEY_FILE)
	@echo "#define ZYPHER_MASTER_KEY_H" >> $(MASTER_KEY_FILE)
	@echo "" >> $(MASTER_KEY_FILE)
	@echo "/* Auto-generated master key for Zypher Encoder/Loader - $(shell date) */" >> $(MASTER_KEY_FILE)
	@echo "/* WARNING: Do not modify or share this file! */" >> $(MASTER_KEY_FILE)
	@echo "" >> $(MASTER_KEY_FILE)
	@echo "#define ZYPHER_MASTER_KEY \"$(shell $(OPENSSL) rand -hex 16)\"" >> $(MASTER_KEY_FILE)
	@echo "" >> $(MASTER_KEY_FILE)
	@echo "/* AES-256 encryption requires a 256-bit key (32 bytes) */" >> $(MASTER_KEY_FILE)
	@echo "#define ZYPHER_KEY_LENGTH 32" >> $(MASTER_KEY_FILE)
	@echo "" >> $(MASTER_KEY_FILE)
	@echo "/* Initialization Vector (IV) for AES-CBC mode */" >> $(MASTER_KEY_FILE)
	@echo "#define ZYPHER_MASTER_IV \"$(shell $(OPENSSL) rand -hex 8)\"" >> $(MASTER_KEY_FILE)
	@echo "" >> $(MASTER_KEY_FILE)
	@echo "#endif /* ZYPHER_MASTER_KEY_H */" >> $(MASTER_KEY_FILE)
	@echo "Master key generated successfully"
	@chmod 644 $(MASTER_KEY_FILE)
	@cp -f $(MASTER_KEY_FILE) $(INCLUDE_DIR)/

# Copy master key to include directory for build process
prepare_loader: $(MASTER_KEY_FILE)
	@mkdir -p $(INCLUDE_DIR)
	@cp -f $(MASTER_KEY_FILE) $(INCLUDE_DIR)/
	@chmod 644 $(INCLUDE_DIR)/$(notdir $(MASTER_KEY_FILE))

# Build the Encoder
encoder: $(ENCODER_BIN)

$(ENCODER_BIN): $(ENCODER_SOURCES) $(INCLUDE_DIR)/zypher_common.h $(INCLUDE_DIR)/zypher_encoder.h $(MASTER_KEY_FILE)
	@echo "Building Zypher Encoder..."
	$(CC) $(CFLAGS) $(ENCODER_SOURCES) -o $@ $(LDFLAGS)
	@echo "Encoder built successfully: $(ENCODER_BIN)"
	@chmod +x $(ENCODER_BIN)

# Clean and reset the loader build environment before building
reset_loader:
	@echo "Cleaning loader build environment..."
	@cd $(LOADER_DIR) && $(PHPIZE) --clean >/dev/null 2>&1 || true
	@rm -rf $(LOADER_DIR)/autom4te.cache $(LOADER_DIR)/build/config.* $(LOADER_DIR)/modules/* 2>/dev/null || true

# Build the Loader PHP Extension with support for debug mode
loader: prepare_loader
	@if [ ! -f $(LOADER_SO) ] || [ -n "$$(find $(LOADER_DIR) -name "*.c" -o -name "*.h" -newer $(LOADER_SO) 2>/dev/null)" ] || [ -n "$$(find $(INCLUDE_DIR) -name "*.h" -newer $(LOADER_SO) 2>/dev/null)" ]; then \
		echo "Building PHP extension loader..."; \
		cd $(LOADER_DIR) && \
		$(PHPIZE) && \
		./configure --with-php-config=$(PHP_CONFIG) --with-openssl=/usr/local/opt/openssl && \
		make CFLAGS="$(CFLAGS) -I$(INCLUDE_DIR)" && \
		cp modules/zypher.so .; \
		echo "PHP extension built successfully: $(LOADER_DIR)/zypher.so"; \
	else \
		echo "Loader is up-to-date, skipping build."; \
	fi

# Build a debug version of the loader with extra diagnostics
debug_loader: prepare_loader reset_loader
	@echo "Building debug version of PHP extension loader..."
	@cd $(LOADER_DIR) && \
	$(PHPIZE) && \
	./configure --with-php-config=$(PHP_CONFIG) --enable-zypher-debug --with-openssl=/usr/local/opt/openssl && \
	make CFLAGS="$(CFLAGS) -I$(INCLUDE_DIR) -DENABLE_ZYPHER_DEBUG=1" && \
	cp modules/zypher.so zypher_debug.so
	@echo "Debug extension built successfully: $(LOADER_DIR)/zypher_debug.so"

# Install the loader to PHP extension directory
install: $(LOADER_DIR)/zypher.so
	@echo "Installing Zypher loader to PHP extensions directory..."
	@cp $(LOADER_DIR)/zypher.so $(PHP_EXTENSION_DIR)
	@echo "Extension installed at: $(PHP_EXTENSION_DIR)/zypher.so"
	@echo "To enable the extension, add 'extension=zypher.so' to your php.ini"

# Create test file for encoding
test_file:
	@mkdir -p $(TEST_DIR)
	@echo "Creating test PHP files..."
	@echo "<?php\n/**\n * Zypher Test Class\n */\nclass ZypherTest {\n    private \$message;\n    \n    public function __construct(\$message = 'Hello from Zypher!') {\n        \$this->message = \$message;\n    }\n    \n    public function getMessage() {\n        return \$this->message;\n    }\n    \n    public function getEncodeTime() {\n        return date('Y-m-d H:i:s');\n    }\n}\n\n\$test = new ZypherTest();\necho \"Message: \" . \$test->getMessage() . \"\\n\";\necho \"Time: \" . \$test->getEncodeTime() . \"\\n\";\n?>" > $(TEST_DIR)/test.php
	@echo "Test PHP file created at $(TEST_DIR)/test.php"

# Test encode and decode process
test:
	@echo "Running Zypher test suite..."
	@chmod +x $(TEST_DIR)/run.sh
	@cd $(TEST_DIR) && ./run.sh
	@echo "Test suite completed"

# Basic quick test for development purposes
quick_test: encoder loader test_file
	@echo "Running quick test for Zypher..."
	@$(ENCODER_BIN) -o $(TEST_DIR)/test.encoded.php $(TEST_DIR)/test.php
	@echo "\nTesting execution of encoded file..."
	@$(PHP_BINARY) -d extension=$(LOADER_DIR)/zypher.so $(TEST_DIR)/test.encoded.php

# Check PHP CLI and system dependencies
check_php:
	@echo "Checking PHP CLI environment for encoder..."
	@which php || echo "ERROR: PHP CLI not found in PATH"
	@php -v || echo "ERROR: PHP CLI not executable"
	@php -m | grep -E 'openssl|opcache' || echo "WARNING: PHP CLI missing required extensions (openssl, opcache)"
	@php -r "if(!function_exists('opcache_compile_file')) echo 'ERROR: PHP opcache extension not loaded or opcache_compile_file() unavailable';"

# Clean build files
clean:
	@echo "Cleaning up build files..."
	@rm -f $(ENCODER_BIN)
	@cd $(LOADER_DIR) && make clean || true
	@cd $(LOADER_DIR) && $(PHPIZE) --clean || true
	@rm -rf $(LOADER_DIR)/autom4te.cache $(LOADER_DIR)/build $(LOADER_DIR)/modules
	@rm -f $(LOADER_DIR)/zypher.so $(LOADER_DIR)/zypher_debug.so
	@rm -f $(TEST_DIR)/test.encoded.php

# Deep clean - also removes the generated master key and test files
distclean: clean
	@echo "Removing all generated files including master key..."
	@rm -f $(MASTER_KEY_FILE)
	@rm -f $(INCLUDE_DIR)/$(notdir $(MASTER_KEY_FILE))
	@rm -f $(TEST_DIR)/test.php

# Show system information for debugging
info:
	@echo "Zypher Build System Information"
	@echo "=============================="
	@echo "PHP Version: $(PHP_VERSION)"
	@echo "PHP Binary: $(PHP_BINARY)"
	@echo "PHP Extension Dir: $(PHP_EXTENSION_DIR)"
	@echo "OpenSSL: $(shell $(OPENSSL) version)"
	@echo "OpenSSL Location: $(shell which $(OPENSSL))"
	@echo "Homebrew OpenSSL: $(shell ls -la /usr/local/opt/openssl 2>/dev/null || echo 'Not found')"
	@echo "Apple OpenSSL: $(shell ls -la /usr/lib/libssl.dylib 2>/dev/null || echo 'Not found')"
	@if [ -f $(MASTER_KEY_FILE) ]; then echo "Master Key File: EXISTS"; else echo "Master Key File: MISSING"; fi
	@if [ -f $(ENCODER_BIN) ]; then echo "Encoder Binary: EXISTS"; else echo "Encoder Binary: NOT BUILT"; fi
	@if [ -f $(LOADER_DIR)/zypher.so ]; then echo "Loader Extension: EXISTS"; else echo "Loader Extension: NOT BUILT"; fi
	@echo "=============================="

.PHONY: all directories master_key prepare_loader reset_loader encoder loader debug_loader install test_file test quick_test clean distclean info check_php