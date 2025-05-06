#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "Zend/zend_hash.h"
#include "ext/standard/md5.h"
#include "ext/standard/sha1.h"
#include "ext/standard/php_string.h"

#include "src/php_loader.h"
#include "security.h"

#include <time.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* Declare external reference to zypher_globals */
#ifdef ZTS
ZEND_TSRMLS_CACHE_EXTERN()
#else
extern zend_zypher_globals zypher_globals;
#endif

/* Helper function to convert binary to hex */
static void bin2hex(unsigned char *bin, size_t bin_len, char *hex)
{
    static const char hex_digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < bin_len; i++)
    {
        hex[i * 2] = hex_digits[(bin[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hex_digits[bin[i] & 0xF];
    }
    hex[bin_len * 2] = '\0';
}

/* Helper function for creating MD5 hash of a string */
static char *md5(const char *input, size_t input_len)
{
    PHP_MD5_CTX context;
    unsigned char digest[16];
    char *output = emalloc(33); /* 32 hex chars + null terminator */
    int i;

    PHP_MD5Init(&context);
    PHP_MD5Update(&context, (unsigned char *)input, input_len);
    PHP_MD5Final(digest, &context);

    for (i = 0; i < 16; i++)
    {
        sprintf(&output[i * 2], "%02x", digest[i]);
    }
    output[32] = '\0';

    return output;
}

/* Check for debugging tools */
int zypher_check_debugger(void)
{
    /* Always use the hardcoded protection setting instead of the INI value */
    if (!ZYPHER_DEBUGGER_PROTECTION)
    {
        if (DEBUG)
            php_printf("DEBUG: Debugger protection is disabled\n");
        return 0; // Protection disabled
    }

#ifdef ZEND_DEBUG
    if (DEBUG)
        php_printf("DEBUG: Running in debug build\n");
    return 1; // Running in debug build
#endif

    // Check for common debuggers
    if (zend_hash_str_exists(&module_registry, "xdebug", sizeof("xdebug") - 1))
    {
        if (DEBUG)
            php_printf("DEBUG: Xdebug module detected\n");
        return 1;
    }

    // Check for assertion being active
    zend_string *key = zend_string_init("assert.active", sizeof("assert.active") - 1, 0);
    zval *value = zend_hash_find(EG(ini_directives), key);
    zend_string_release(key);

    if (value && Z_TYPE_P(value) == IS_STRING &&
        Z_STRLEN_P(value) == 1 && Z_STRVAL_P(value)[0] == '1')
    {
        if (DEBUG)
            php_printf("DEBUG: PHP assertions are active\n");
        return 1;
    }

    if (DEBUG)
        php_printf("DEBUG: No debugger detected\n");
    return 0;
}

/* Verify license (domain and expiry) */
int zypher_verify_license(const char *domain, time_t timestamp)
{
    // Check expiry if set
    if (ZYPHER_G(license_expiry) > 0 && time(NULL) > ZYPHER_G(license_expiry))
    {
        if (DEBUG)
            php_printf("DEBUG: License expired (current: %ld, expiry: %ld)\n",
                       (long)time(NULL), (long)ZYPHER_G(license_expiry));
        return ZYPHER_ERR_EXPIRED;
    }

    // Check domain if set
    if (ZYPHER_G(license_domain) && *ZYPHER_G(license_domain))
    {
        char *server_name = NULL;

        // Try to get server name
        zval *server_zval;
        zval *server_name_zval;

        // Check if _SERVER is available
        if ((server_zval = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1)) != NULL &&
            Z_TYPE_P(server_zval) == IS_ARRAY &&
            (server_name_zval = zend_hash_str_find(Z_ARRVAL_P(server_zval), "SERVER_NAME", sizeof("SERVER_NAME") - 1)) != NULL)
        {
            // Convert to string if needed
            zval tmp_zval;
            if (Z_TYPE_P(server_name_zval) != IS_STRING)
            {
                tmp_zval = *server_name_zval;
                zval_copy_ctor(&tmp_zval);
                convert_to_string(&tmp_zval);
                server_name = Z_STRVAL(tmp_zval);
            }
            else
            {
                server_name = Z_STRVAL_P(server_name_zval);
            }

            // Compare domain
            if (server_name && strcmp(server_name, ZYPHER_G(license_domain)) != 0)
            {
                if (DEBUG)
                    php_printf("DEBUG: Domain mismatch (current: %s, licensed: %s)\n",
                               server_name, ZYPHER_G(license_domain));
                // Domain mismatch
                return ZYPHER_ERR_DOMAIN;
            }

            if (DEBUG)
                php_printf("DEBUG: Domain validation passed: %s\n", server_name);
        }
        else if (DEBUG)
        {
            php_printf("DEBUG: _SERVER or SERVER_NAME not available for domain verification\n");
        }
    }

    return ZYPHER_ERR_NONE;
}

/* Enhanced key derivation function using OpenSSL directly with multiple iterations.
 * Must match the function in the encoder exactly - direct port of PHP encoder's code */
void zypher_derive_key(const char *master_key, const char *filename, char *output_key, int iterations)
{
    unsigned char digest[32]; /* SHA-256 produces 32 bytes */
    char salt[100];
    int i;

    if (DEBUG)
    {
        php_printf("DEBUG: Deriving key for file %s (iterations: %d)\n", filename, iterations);
        php_printf("DEBUG: Master key: '%s'\n", master_key);
    }

    /* Add a salt based on a combination of factors
     * CRITICAL - This must exactly match the encoder's implementation */
    char *filename_md5 = md5(filename, strlen(filename));
    snprintf(salt, sizeof(salt), "ZypherSalt-%s", filename_md5);

    if (DEBUG)
    {
        php_printf("DEBUG: Using salt: %s (from MD5 of filename: %s)\n", salt, filename_md5);
    }

    efree(filename_md5); /* Free the allocated md5 string */

    /* Initialize variables to match PHP exactly */
    unsigned char *derived_key = emalloc(32);
    unsigned int derived_len = 32;

    /* FIX: This exactly mirrors the PHP code:
     * $salt = 'ZypherSalt-' . md5($filename);
     * $derivedKey = hash_hmac('sha256', $filename . $salt, $masterKey, true);
     */
    // Combine filename and salt exactly like PHP does
    char *combined_data = emalloc(strlen(filename) + strlen(salt) + 1);
    strcpy(combined_data, filename);
    strcat(combined_data, salt);

    // Perform the initial HMAC with the combined data
    HMAC(EVP_sha256(), master_key, strlen(master_key),
         (unsigned char *)combined_data, strlen(combined_data),
         derived_key, &derived_len);

    // Free the combined data buffer
    efree(combined_data);

    if (DEBUG)
    {
        char hex_digest[65];
        for (i = 0; i < 32; i++)
            sprintf(&hex_digest[i * 2], "%02x", derived_key[i]);
        hex_digest[64] = '\0';
        php_printf("DEBUG: Initial HMAC result: %s\n", hex_digest);
    }

    /*
     * This exactly mirrors the PHP code:
     * for ($i = 0; $i < $iterations; $i++) {
     *     $derivedKey = hash_hmac('sha256', $derivedKey . $salt . chr($i & 0xFF), $masterKey, true);
     * }
     */
    for (i = 0; i < iterations; i++)
    {
        /* Build the buffer exactly as PHP would */
        unsigned char *buffer = emalloc(32 + strlen(salt) + 1);
        unsigned int buffer_len = 0;

        /* Copy the current derived key */
        memcpy(buffer, derived_key, 32);
        buffer_len += 32;

        /* Add the salt */
        memcpy(buffer + buffer_len, salt, strlen(salt));
        buffer_len += strlen(salt);

        /* Add the iteration counter as a byte */
        buffer[buffer_len++] = (unsigned char)(i & 0xFF);

        /* Perform HMAC */
        HMAC(EVP_sha256(), master_key, strlen(master_key),
             buffer, buffer_len, derived_key, &derived_len);

        /* Free the buffer */
        efree(buffer);
    }

    /* Convert final binary digest to hex string - matches bin2hex() in PHP */
    for (i = 0; i < 32; i++)
    {
        sprintf(&output_key[i * 2], "%02x", derived_key[i]);
    }
    output_key[64] = '\0';

    /* Free the derived key */
    efree(derived_key);

    if (DEBUG)
    {
        php_printf("DEBUG: Final derived key: %s\n", output_key);
    }
}