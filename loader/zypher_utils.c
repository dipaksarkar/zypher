/*
  +----------------------------------------------------------------------+
  | Zypher PHP Loader                                                    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2023-2025 Zypher Team                                  |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Zypher Team <info@zypher.com>                                |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/base64.h"
#include "Zend/zend_compile.h"
#include "main/php_main.h" /* For php_sapi_name() */
#include "main/SAPI.h"     /* For SAPI-related functions */

#include "php_zypher.h"
#include <openssl/evp.h>
#include <openssl/err.h>

/* Function to directly decode an encoded string (for testing/debugging) */
PHP_FUNCTION(zypher_decode_string)
{
    char *str = NULL;
    size_t str_len;
    char *key = NULL;
    size_t key_len;

    /* Parse parameters: accepts a hex string and key */
    ZEND_PARSE_PARAMETERS_START(2, 2)
    Z_PARAM_STRING(str, str_len)
    Z_PARAM_STRING(key, key_len)
    ZEND_PARSE_PARAMETERS_END();

    if (str_len == 0 || key_len == 0)
    {
        RETURN_FALSE;
    }

    /* Create initialization vector (16 bytes for AES) */
    unsigned char iv[16] = {0};
    const char *iv_str = "ZypherIV12345678"; /* Simple IV for the test function */
    memcpy(iv, iv_str, MIN(16, strlen(iv_str)));

    /* Create OpenSSL cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        php_error_docref(NULL, E_WARNING, "Failed to create cipher context");
        RETURN_FALSE;
    }

    /* Select AES-256-CBC cipher */
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();

    /* Initialize decryption */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char *)key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        php_error_docref(NULL, E_WARNING, "Failed to initialize decryption");
        RETURN_FALSE;
    }

    /* Prepare output buffer (allow space for padding) */
    unsigned char *outbuf = emalloc(str_len + EVP_MAX_BLOCK_LENGTH);
    int outlen, tmplen;

    /* Convert hex string to binary if needed */
    unsigned char *binstr = NULL;
    size_t binstr_len = 0;

    /* Check if input is base64 */
    if (str[str_len - 1] == '=' || str[str_len - 2] == '=')
    {
        /* Looks like base64, try to decode */
        zend_string *decoded = php_base64_decode((unsigned char *)str, str_len);
        if (decoded)
        {
            binstr = (unsigned char *)ZSTR_VAL(decoded);
            binstr_len = ZSTR_LEN(decoded);
        }
    }
    else
    {
        /* Assume it's already binary */
        binstr = (unsigned char *)estrndup(str, str_len);
        binstr_len = str_len;
    }

    if (!binstr || binstr_len == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        efree(outbuf);
        php_error_docref(NULL, E_WARNING, "Invalid input string format");
        RETURN_FALSE;
    }

    /* Perform decryption */
    if (EVP_DecryptUpdate(ctx, outbuf, &outlen, binstr, binstr_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        efree(outbuf);
        efree(binstr);
        php_error_docref(NULL, E_WARNING, "Decryption operation failed");
        RETURN_FALSE;
    }

    /* Finalize decryption */
    if (EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        efree(outbuf);
        efree(binstr);
        php_error_docref(NULL, E_WARNING, "Failed to finalize decryption");
        RETURN_FALSE;
    }

    /* Set total length */
    outlen += tmplen;

    /* Create return string */
    RETVAL_STRINGL((char *)outbuf, outlen);

    /* Cleanup */
    EVP_CIPHER_CTX_free(ctx);
    efree(outbuf);
    efree(binstr);
}

/* Utility function to display a hex dump of binary data (helpful for debugging) */
void zypher_hex_dump(const unsigned char *data, size_t len)
{
    if (!DEBUG || !data || len == 0)
    {
        return;
    }

    php_printf("DEBUG: Hex dump of %zu bytes:\n", len);
    php_printf("       0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF\n");
    php_printf("       -------------------------------------------------------  ----------------\n");

    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';

    for (i = 0; i < len; i++)
    {
        if ((i % 16) == 0)
        {
            if (i != 0)
            {
                php_printf("  %s\n", ascii);
            }
            php_printf("%04zX: ", i);
        }

        php_printf("%02X ", data[i]);

        /* Store printable ASCII characters */
        ascii[i % 16] = (data[i] >= ' ' && data[i] <= '~') ? data[i] : '.';
    }

    /* Pad the last line with spaces if necessary */
    if ((i % 16) != 0)
    {
        for (j = i % 16; j < 16; j++)
        {
            php_printf("   ");
            ascii[j] = ' ';
        }
    }

    php_printf("  %s\n", ascii);
}

/* Log a message to the PHP error log or stdout in debug mode */
void zypher_log_message(const char *format, ...)
{
    if (!DEBUG)
    {
        return;
    }

    va_list args;
    char buffer[4096];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    /* In CLI mode, print to stdout; otherwise use error_log */
    const char *sapi_name = sapi_module.name;
    if (sapi_name && !strcmp(sapi_name, "cli"))
    {
        php_printf("[ZYPHER] %s\n", buffer);
    }
    else
    {
        php_error_docref(NULL, E_NOTICE, "%s", buffer);
    }
}