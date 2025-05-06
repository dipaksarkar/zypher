#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"

#include "src/php_loader.h"
#include "utils.h"

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/**
 * Helper function to convert a hexadecimal character to its integer value
 *
 * @param c The hex character (0-9, a-f, A-F)
 * @return The integer value of the hex character or 16 if invalid
 */
static unsigned char hex_to_int(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 16; // Invalid hex character
}

/**
 * Native implementation of string decoding for obfuscation
 * This replaces the PHP-based zypher_decode_str function with a native C implementation
 */
PHP_FUNCTION(zypher_decode_string)
{
    char *hex_str = NULL, *key = NULL;
    size_t hex_len, key_len;

    // Get parameters: the hex-encoded string and the key
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &hex_str, &hex_len, &key, &key_len) == FAILURE)
    {
        RETURN_NULL();
    }

    // Validate inputs
    if (hex_len == 0 || key_len == 0)
    {
        RETURN_EMPTY_STRING();
    }

    if (DEBUG)
    {
        php_printf("DEBUG: zypher_decode_string called with hex_len=%zu, key_len=%zu\n", hex_len, key_len);
        php_printf("DEBUG: First 20 chars of hex: %.20s...\n", hex_str);
    }

    // Binary size is half of hex size (2 hex chars = 1 byte)
    size_t bin_len = hex_len / 2;
    unsigned char *bin_data = emalloc(bin_len + 1);
    size_t pos = 0;

    // Convert hex to binary
    for (size_t i = 0; i < hex_len; i += 2)
    {
        unsigned char high = hex_to_int(hex_str[i]);
        unsigned char low = hex_to_int(hex_str[i + 1]);
        if (high > 15 || low > 15)
        {
            // Invalid hex character
            efree(bin_data);
            if (DEBUG)
                php_printf("DEBUG: Invalid hex characters at position %zu\n", i);
            RETURN_NULL();
        }
        bin_data[pos++] = (high << 4) | low;
    }
    bin_data[bin_len] = '\0';

    // Allocate buffer for decrypted string
    char *result = emalloc(bin_len + 1);

    // XOR decryption with key
    for (size_t i = 0; i < bin_len; i++)
    {
        result[i] = bin_data[i] ^ key[i % key_len];
    }
    result[bin_len] = '\0';

    if (DEBUG)
    {
        php_printf("DEBUG: Decoded string (first 20 chars): %.20s...\n", result);
    }

    // Free binary data
    efree(bin_data);

    // Return the decoded string
    RETURN_STRING(result);
}