/**
 * Utility functions for Zypher PHP Extension
 */
#ifndef ZYPHER_UTILS_H
#define ZYPHER_UTILS_H

#include "php.h"
#include "src/php_loader.h"

/* PHP function for string decoding */
PHP_FUNCTION(zypher_decode_string);

/* Enhanced key derivation using HMAC-SHA256 with multiple iterations */
void zypher_derive_key(const char *master_key, const char *filename, char *output_key, int iterations);

#endif /* ZYPHER_UTILS_H */