#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/base64.h"
#include "ext/standard/md5.h"
#include "Zend/zend_compile.h"
#include "php_loader.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <time.h>
#include <libgen.h> /* For basename() function */

/* Store original compile file function */
zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);

/* Constants for file format */
#define ZYPHER_SIGNATURE "ZYPH01"
#define SIGNATURE_LENGTH 6
#define IV_LENGTH 16
#define KEY_HMAC_LENGTH 32
#define ZYPHER_FORMAT_VERSION 1
#define MAX_KEY_ITERATIONS 1000
#define ZYPHER_ERR_NONE 0
#define ZYPHER_ERR_EXPIRED 1
#define ZYPHER_ERR_DOMAIN 2
#define ZYPHER_ERR_TAMPERED 3

/* For compatibility with PHP thread safety */
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#else
/* Define globals instance for non-thread safe build */
ZEND_DECLARE_MODULE_GLOBALS(zypher)
#endif

/* Function declarations for module init, shutdown, and info */
PHP_MINIT_FUNCTION(zypher);
PHP_MSHUTDOWN_FUNCTION(zypher);
PHP_MINFO_FUNCTION(zypher);

/* Add proper arginfo for zypher_decode_string function */
ZEND_BEGIN_ARG_INFO_EX(arginfo_zypher_decode_string, 0, 0, 2)
ZEND_ARG_INFO(0, hex_string)
ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

/* Add the function entry for our string decoder with proper arginfo */
static const zend_function_entry zypher_functions[] = {
    PHP_FE(zypher_decode_string, arginfo_zypher_decode_string)
        PHP_FE_END};

/* Module configuration entries */
PHP_INI_BEGIN()
PHP_INI_ENTRY("zypher.debugger_protection", "1", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("zypher.license_domain", "", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("zypher.license_expiry", "0", PHP_INI_ALL, NULL)
PHP_INI_END()

/* Define the module entry */
zend_module_entry zypher_module_entry = {
    STANDARD_MODULE_HEADER,
    "zypher",              /* Extension name */
    zypher_functions,      /* Function entries */
    PHP_MINIT(zypher),     /* Module init */
    PHP_MSHUTDOWN(zypher), /* Module shutdown */
    NULL,                  /* Request init */
    NULL,                  /* Request shutdown */
    PHP_MINFO(zypher),     /* Module info */
    PHP_ZYPHER_VERSION,    /* Version */
    STANDARD_MODULE_PROPERTIES};

/* Compile module */
ZEND_GET_MODULE(zypher)

/* Init globals */
static void php_zypher_init_globals(zend_zypher_globals *globals)
{
    globals->license_domain = NULL;
    globals->license_expiry = 0;
    globals->debugger_protection = 1;
    globals->self_healing = 0;
    memset(globals->anti_tamper_hash, 0, sizeof(globals->anti_tamper_hash));
}

/* Check for debugging tools */
int zypher_check_debugger(void)
{
    if (!ZYPHER_G(debugger_protection))
    {
        return 0; // Protection disabled
    }

#ifdef ZEND_DEBUG
    return 1; // Running in debug build
#endif

    // Check for common debuggers
    if (zend_hash_str_exists(&module_registry, "xdebug", sizeof("xdebug") - 1))
    {
        return 1;
    }

    // Check for assertion being active
    zend_string *key = zend_string_init("assert.active", sizeof("assert.active") - 1, 0);
    zval *value = zend_hash_find(EG(ini_directives), key);
    zend_string_release(key);

    if (value && Z_TYPE_P(value) == IS_STRING &&
        Z_STRLEN_P(value) == 1 && Z_STRVAL_P(value)[0] == '1')
    {
        return 1;
    }

    return 0;
}

/* Verify license (domain and expiry) */
int zypher_verify_license(const char *domain, time_t timestamp)
{
    // Check expiry if set
    if (ZYPHER_G(license_expiry) > 0 && time(NULL) > ZYPHER_G(license_expiry))
    {
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
                // Domain mismatch
                return ZYPHER_ERR_DOMAIN;
            }
        }
    }

    return ZYPHER_ERR_NONE;
}

/* Enhanced key derivation using HMAC-SHA256 with multiple iterations */
void zypher_derive_key(const char *master_key, const char *filename, char *output_key, int iterations)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char salt[128];

    // Create a salt based on filename
    snprintf(salt, sizeof(salt), "ZypherSalt-%s", filename);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // Initial HMAC
    HMAC(EVP_sha256(), master_key, strlen(master_key),
         (unsigned char *)salt, strlen(salt), hash, NULL);

    // Multiple iterations for key strengthening
    for (int i = 0; i < iterations && i < MAX_KEY_ITERATIONS; i++)
    {
        // Add iteration counter to salt
        snprintf(salt, sizeof(salt), "ZypherSalt-%s-%d", filename, i);
        HMAC(EVP_sha256(), master_key, strlen(master_key),
             hash, sizeof(hash), hash, NULL);
    }
#else
    /* Create context for HMAC-SHA256 */
    HMAC_CTX *ctx = HMAC_CTX_new();

    /* Initialize with master key */
    HMAC_Init_ex(ctx, master_key, strlen(master_key), EVP_sha256(), NULL);

    /* Add salted filename to the mix */
    HMAC_Update(ctx, (unsigned char *)salt, strlen(salt));

    /* Finalize */
    unsigned int len = SHA256_DIGEST_LENGTH;
    HMAC_Final(ctx, hash, &len);

    /* Multiple iterations for key strengthening */
    for (int i = 0; i < iterations && i < MAX_KEY_ITERATIONS; i++)
    {
        HMAC_CTX_reset(ctx);
        HMAC_Init_ex(ctx, master_key, strlen(master_key), EVP_sha256(), NULL);
        HMAC_Update(ctx, hash, sizeof(hash));
        HMAC_Update(ctx, (unsigned char *)&i, sizeof(i));
        HMAC_Final(ctx, hash, &len);
    }

    HMAC_CTX_free(ctx);
#endif

    /* Convert to hex string */
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(output_key + (i * 2), "%02x", hash[i]);
    }
    output_key[SHA256_DIGEST_LENGTH * 2] = '\0';
}

/* Module init */
PHP_MINIT_FUNCTION(zypher)
{
#if defined(ZTS) && defined(COMPILE_DL_ZYPHER)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    ZEND_INIT_MODULE_GLOBALS(zypher, php_zypher_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Save original compile file function */
    original_compile_file = zend_compile_file;

    /* Replace with our handler */
    zend_compile_file = zypher_compile_file;

    return SUCCESS;
}

/* Module shutdown */
PHP_MSHUTDOWN_FUNCTION(zypher)
{
    /* Restore original compile file function */
    zend_compile_file = original_compile_file;

    /* Cleanup OpenSSL */
    EVP_cleanup();
    ERR_free_strings();

    UNREGISTER_INI_ENTRIES();

    return SUCCESS;
}

/* Module info */
PHP_MINFO_FUNCTION(zypher)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "Zypher Support", "enabled");
    php_info_print_table_row(2, "Version", PHP_ZYPHER_VERSION);
    php_info_print_table_row(2, "OpenSSL Support", "enabled");
    php_info_print_table_row(2, "File Format", "encrypted (AES-256-CBC)");
    php_info_print_table_row(2, "Anti-debugging", ZYPHER_G(debugger_protection) ? "enabled" : "disabled");
    php_info_print_table_row(2, "Advanced Obfuscation", "enabled");
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}

static char *read_file_contents(const char *filename, size_t *size)
{
    php_stream *stream;
    char *contents;
    size_t file_size;
    php_stream_statbuf stat_buf;

    stream = php_stream_open_wrapper((char *)filename, "rb", REPORT_ERRORS, NULL);
    if (!stream)
    {
        return NULL;
    }

    /* Determine file size using proper stat_buf structure */
    if (php_stream_stat(stream, &stat_buf) != 0)
    {
        php_stream_close(stream);
        return NULL;
    }

    file_size = stat_buf.sb.st_size;

    /* Allocate memory for file contents */
    contents = emalloc(file_size + 1);
    if (!contents)
    {
        php_stream_close(stream);
        return NULL;
    }

    /* Read file contents */
    if (php_stream_read(stream, contents, file_size) != file_size)
    {
        efree(contents);
        php_stream_close(stream);
        return NULL;
    }

    /* Null terminate */
    contents[file_size] = '\0';

    /* Close stream */
    php_stream_close(stream);

    if (size)
    {
        *size = file_size;
    }

    return contents;
}

/* Check if content has been tampered with via checksum */
static int verify_content_integrity(const char *content, size_t content_len, const char *checksum)
{
    char calculated_checksum[33];
    PHP_MD5_CTX context;
    unsigned char digest[16];

    // Calculate MD5 of content
    PHP_MD5Init(&context);
    PHP_MD5Update(&context, (unsigned char *)content, content_len);
    PHP_MD5Final(digest, &context);

    // Convert to hex string
    for (int i = 0; i < 16; i++)
    {
        sprintf(calculated_checksum + (i * 2), "%02x", digest[i]);
    }
    calculated_checksum[32] = '\0';

    // Compare
    return strcmp(calculated_checksum, checksum) == 0 ? ZYPHER_ERR_NONE : ZYPHER_ERR_TAMPERED;
}

/* Enhanced decrypt function that handles advanced format and obfuscation */
static char *decrypt_file_content(const char *encoded_content, size_t encoded_length,
                                  const char *master_key, const char *filename, size_t *out_length)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    unsigned char iv[IV_LENGTH];
    unsigned char master_iv[IV_LENGTH];
    char *decrypted = NULL;
    int outlen, tmplen;
    zend_string *decoded_str;
    char file_key[65]; /* 64 hex chars + null */
    char *encrypted_file_key = NULL;
    char *orig_filename = NULL;
    uint32_t key_length = 0;
    uint8_t filename_length = 0;
    size_t pos = 0;
    char debug_hex[128];
    int format_version = 0;
    uint32_t timestamp = 0;
    int has_byte_rotation = 0;
    char extracted_checksum[33] = {0};

    /* New variables for enhanced format */
    int security_flags = 0;

    // Debug output
    if (DEBUG)
    {
        php_printf("DEBUG: Decrypting content of length %zu\n", encoded_length);
    }

    /* Base64 decode first */
    decoded_str = php_base64_decode((const unsigned char *)encoded_content, encoded_length);
    if (!decoded_str)
    {
        if (DEBUG)
            php_printf("DEBUG: Base64 decoding failed\n");
        return NULL;
    }

    if (DEBUG)
    {
        php_printf("DEBUG: Base64 decoded length: %zu bytes\n", ZSTR_LEN(decoded_str));
    }

    /* Check for byte rotation */
    char *rotated_content = NULL;

    /* Handle byte rotation if this is the enhanced format */
    if (ZSTR_LEN(decoded_str) > 0)
    {
        /* Simple heuristic: check if first byte is likely version byte (1) */
        if ((unsigned char)ZSTR_VAL(decoded_str)[0] == (1 + 7) % 256)
        {
            has_byte_rotation = 1;

            if (DEBUG)
            {
                php_printf("DEBUG: Detected byte rotation encoding\n");
            }

            /* Un-rotate bytes (reverse +7 rotation) */
            rotated_content = emalloc(ZSTR_LEN(decoded_str) + 1);
            for (size_t i = 0; i < ZSTR_LEN(decoded_str); i++)
            {
                rotated_content[i] = (char)((unsigned char)(ZSTR_VAL(decoded_str)[i]) - 7) & 0xFF;
            }
            rotated_content[ZSTR_LEN(decoded_str)] = '\0';

            /* Use the rotated content instead of the original */
            zend_string *old_str = decoded_str;
            decoded_str = zend_string_init(rotated_content, ZSTR_LEN(old_str), 0);
            zend_string_release(old_str);
            efree(rotated_content);
        }
    }

    /* Check if this is debug mode or production mode */
    if (ZSTR_LEN(decoded_str) > 0 && ZSTR_VAL(decoded_str)[0] == '<')
    {
        /* This appears to be raw PHP code (debug mode) - no further decryption needed */
        if (DEBUG)
            php_printf("DEBUG: Detected debug mode encoding (direct base64)\n");

        /* Return a copy of the decoded content */
        decrypted = emalloc(ZSTR_LEN(decoded_str) + 1);
        memcpy(decrypted, ZSTR_VAL(decoded_str), ZSTR_LEN(decoded_str));
        decrypted[ZSTR_LEN(decoded_str)] = '\0';

        if (out_length)
        {
            *out_length = ZSTR_LEN(decoded_str);
        }

        zend_string_release(decoded_str);
        return decrypted;
    }

    /* Production mode - handle enhanced format */
    if (DEBUG)
        php_printf("DEBUG: Production mode detected - processing enhanced format\n");

    /* Check minimum size for new format */
    if (ZSTR_LEN(decoded_str) <= 1 + 4 + (IV_LENGTH * 2) + 4)
    {
        if (DEBUG)
            php_printf("DEBUG: Decoded data too short for format header\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Check for enhanced format (version byte) */
    format_version = (unsigned char)ZSTR_VAL(decoded_str)[pos++];

    if (DEBUG)
    {
        php_printf("DEBUG: Format version: %d\n", format_version);
    }

    /* Process according to format version */
    if (format_version == ZYPHER_FORMAT_VERSION)
    {
        /* Enhanced format with timestamp */
        memcpy(&timestamp, ZSTR_VAL(decoded_str) + pos, 4);
        timestamp = ntohl(timestamp); /* Network to host byte order */
        pos += 4;

        if (DEBUG)
        {
            php_printf("DEBUG: Timestamp: %u (%s)\n", timestamp, ctime((time_t *)&timestamp));
        }

        /* License verification */
        int license_result = zypher_verify_license(NULL, timestamp);
        if (license_result != ZYPHER_ERR_NONE)
        {
            if (license_result == ZYPHER_ERR_EXPIRED)
            {
                php_error_docref(NULL, E_WARNING, "License expired");
            }
            else if (license_result == ZYPHER_ERR_DOMAIN)
            {
                php_error_docref(NULL, E_WARNING, "Domain not licensed");
            }
            zend_string_release(decoded_str);
            return NULL;
        }
    }

    /* Anti-debugging check */
    if (zypher_check_debugger())
    {
        php_error_docref(NULL, E_WARNING, "Debugging tools detected, execution denied");
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract IVs */
    memcpy(iv, ZSTR_VAL(decoded_str) + pos, IV_LENGTH);
    pos += IV_LENGTH;

    if (DEBUG)
    {
        /* Convert IV to hex for debugging */
        for (int i = 0; i < IV_LENGTH; i++)
        {
            sprintf(debug_hex + (i * 2), "%02x", iv[i]);
        }
        debug_hex[IV_LENGTH * 2] = '\0';
        php_printf("DEBUG: Extracted content IV (hex): %s\n", debug_hex);
    }

    memcpy(master_iv, ZSTR_VAL(decoded_str) + pos, IV_LENGTH);
    pos += IV_LENGTH;

    if (DEBUG)
    {
        /* Convert master IV to hex for debugging */
        for (int i = 0; i < IV_LENGTH; i++)
        {
            sprintf(debug_hex + (i * 2), "%02x", master_iv[i]);
        }
        debug_hex[IV_LENGTH * 2] = '\0';
        php_printf("DEBUG: Extracted key IV (hex): %s\n", debug_hex);
    }

    /* Read key length (4 bytes, big-endian) */
    memcpy(&key_length, ZSTR_VAL(decoded_str) + pos, 4);
    key_length = ntohl(key_length); /* Convert from network byte order to host byte order */
    pos += 4;

    if (DEBUG)
    {
        php_printf("DEBUG: Extracted key length: %u bytes\n", key_length);
    }

    /* Validate key length to prevent buffer overflows */
    if (key_length > 1024 || pos + key_length > ZSTR_LEN(decoded_str))
    {
        if (DEBUG)
        {
            php_printf("DEBUG: Invalid key length %u (buffer size: %zu, pos: %zu)\n",
                       key_length, ZSTR_LEN(decoded_str), pos);
        }
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract encrypted file key */
    encrypted_file_key = emalloc(key_length + 1);
    memcpy(encrypted_file_key, ZSTR_VAL(decoded_str) + pos, key_length);
    encrypted_file_key[key_length] = '\0';
    pos += key_length;

    if (DEBUG)
    {
        /* Convert part of encrypted key to hex for debugging */
        int hex_bytes = key_length > 16 ? 16 : key_length;
        for (int i = 0; i < hex_bytes; i++)
        {
            sprintf(debug_hex + (i * 2), "%02x", (unsigned char)encrypted_file_key[i]);
        }
        debug_hex[hex_bytes * 2] = '\0';
        php_printf("DEBUG: Extracted encrypted file key (first %d bytes in hex): %s\n",
                   hex_bytes, debug_hex);
    }

    /* Read original filename length (1 byte) */
    if (pos >= ZSTR_LEN(decoded_str))
    {
        if (DEBUG)
        {
            php_printf("DEBUG: File format error: no space for filename length byte\n");
        }
        efree(encrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    filename_length = (uint8_t)ZSTR_VAL(decoded_str)[pos++];

    if (DEBUG)
    {
        php_printf("DEBUG: Original filename length: %u bytes\n", filename_length);
    }

    /* Validate filename length */
    if (filename_length == 0 || pos + filename_length > ZSTR_LEN(decoded_str))
    {
        if (DEBUG)
        {
            php_printf("DEBUG: Invalid filename length: %u (buffer size: %zu, pos: %zu)\n",
                       filename_length, ZSTR_LEN(decoded_str), pos);
        }
        efree(encrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract original filename */
    orig_filename = emalloc(filename_length + 1);
    memcpy(orig_filename, ZSTR_VAL(decoded_str) + pos, filename_length);
    orig_filename[filename_length] = '\0';
    pos += filename_length;

    if (DEBUG)
    {
        php_printf("DEBUG: Extracted original filename: '%s'\n", orig_filename);
    }

    /* Derive master key using enhanced algorithm with multiple iterations */
    zypher_derive_key(master_key, orig_filename, file_key, 1000);

    if (DEBUG)
    {
        php_printf("DEBUG: Derived file key: %s\n", file_key);
    }

    /* Create decryption context for file key */
    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_aes_256_cbc();

    /* Initialize key decryption operation with derived master key */
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char *)file_key, master_iv))
    {
        if (DEBUG)
        {
            php_printf("DEBUG: Key decryption initialization failed\n");
        }
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Allocate buffer for decrypted file key */
    char *decrypted_file_key = emalloc(key_length + EVP_CIPHER_block_size(cipher));
    int file_key_len = 0, file_key_tmplen = 0;

    /* Decrypt the file key */
    if (!EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_file_key, &file_key_len,
                           (unsigned char *)encrypted_file_key, key_length))
    {
        if (DEBUG)
        {
            php_printf("DEBUG: Key decryption update failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        }
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Finalize key decryption */
    if (!EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted_file_key + file_key_len, &file_key_tmplen))
    {
        if (DEBUG)
        {
            php_printf("DEBUG: Key decryption finalization failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            php_printf("DEBUG: This often happens due to padding issues or incorrect key/IV\n");
        }
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    file_key_len += file_key_tmplen;
    decrypted_file_key[file_key_len] = '\0';

    if (DEBUG)
    {
        php_printf("DEBUG: File key decrypted successfully (length: %d bytes)\n", file_key_len);
    }

    /* Clean up key decryption context */
    EVP_CIPHER_CTX_free(ctx);
    efree(encrypted_file_key);
    efree(orig_filename); /* Clean up original filename buffer */

    /* Now use the decrypted file key to decrypt the content */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialize content decryption */
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char *)decrypted_file_key, iv))
    {
        if (DEBUG)
        {
            php_printf("DEBUG: Content decryption init failed\n");
        }
        EVP_CIPHER_CTX_free(ctx);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Allocate memory for decrypted content */
    size_t content_length = ZSTR_LEN(decoded_str) - pos;

    if (DEBUG)
    {
        php_printf("DEBUG: Content length to decrypt: %zu bytes\n", content_length);
    }

    decrypted = emalloc(content_length + EVP_CIPHER_block_size(cipher));

    /* Decrypt the content */
    if (!EVP_DecryptUpdate(ctx, (unsigned char *)decrypted, &outlen,
                           (unsigned char *)ZSTR_VAL(decoded_str) + pos, content_length))
    {
        if (DEBUG)
        {
            php_printf("DEBUG: Content decryption update failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        }
        EVP_CIPHER_CTX_free(ctx);
        efree(decrypted_file_key);
        efree(decrypted);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Finalize content decryption */
    if (!EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted + outlen, &tmplen))
    {
        if (DEBUG)
        {
            php_printf("DEBUG: Content decryption finalization failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        }
        EVP_CIPHER_CTX_free(ctx);
        efree(decrypted_file_key);
        efree(decrypted);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    /* Set output length */
    int total_decrypted_len = outlen + tmplen;
    if (out_length)
    {
        *out_length = total_decrypted_len;
    }

    /* Null terminate the decrypted content */
    decrypted[total_decrypted_len] = '\0';

    if (DEBUG)
    {
        php_printf("DEBUG: Content decrypted successfully, length: %d bytes\n", total_decrypted_len);
    }

    /* Check if we have a checksum in the enhanced format */
    if (format_version == ZYPHER_FORMAT_VERSION)
    {
        /* Extract MD5 checksum (32 chars) from beginning of decrypted content */
        memcpy(extracted_checksum, decrypted, 32);
        extracted_checksum[32] = '\0';

        if (DEBUG)
        {
            php_printf("DEBUG: Extracted checksum: %s\n", extracted_checksum);
        }

        /* Verify checksum */
        char *actual_content = decrypted + 32;
        int content_len = total_decrypted_len - 32;

        if (verify_content_integrity(actual_content, content_len, extracted_checksum) != ZYPHER_ERR_NONE)
        {
            php_error_docref(NULL, E_WARNING, "File integrity verification failed - content may be tampered");
            efree(decrypted_file_key);
            efree(decrypted);
            zend_string_release(decoded_str);
            return NULL;
        }

        if (DEBUG)
        {
            php_printf("DEBUG: Content integrity verified\n");
        }

        /* Move the actual content to the beginning of the buffer */
        memmove(decrypted, actual_content, content_len + 1); // +1 for the null terminator

        /* Update output length */
        if (out_length)
        {
            *out_length = content_len;
        }
    }

    efree(decrypted_file_key);
    zend_string_release(decoded_str);

    return decrypted;
}

/* Custom zend_compile_file function to handle encoded files */
zend_op_array *zypher_compile_file(zend_file_handle *file_handle, int type)
{
    char *buffer = NULL;
    size_t buffer_len = 0;
    char *decoded = NULL;
    size_t decoded_len = 0;
    char signature[SIGNATURE_LENGTH + 1] = {0};
    int is_encoded = 0;
    zend_op_array *op_array = NULL;
    zend_file_handle decoded_file_handle;
    char file_key[65] = {0}; /* 64 hex chars + null */
    const char *filename;

    /* Skip if no file or already processed */
    if (!file_handle || !file_handle->filename)
    {
        if (DEBUG)
            php_printf("DEBUG: No filename provided to zypher_compile_file\n");
        return original_compile_file(file_handle, type);
    }

    /* Handle zend_string filename in PHP 8.x */
    filename = ZSTR_VAL(file_handle->filename);

    if (DEBUG)
        php_printf("DEBUG: Checking file: %s\n", filename);

    /* Read the file contents */
    buffer = read_file_contents(filename, &buffer_len);
    if (!buffer || buffer_len < SIGNATURE_LENGTH)
    {
        /* Not our file or couldn't read it */
        if (buffer)
        {
            efree(buffer);
        }
        if (DEBUG)
            php_printf("DEBUG: File too small or couldn't be read\n");
        return original_compile_file(file_handle, type);
    }

    /* Check for our signature */
    memcpy(signature, buffer, SIGNATURE_LENGTH);
    signature[SIGNATURE_LENGTH] = '\0';

    if (DEBUG)
    {
        php_printf("DEBUG: File signature: %s (expected: %s)\n", signature, ZYPHER_SIGNATURE);
    }

    if (strcmp(signature, ZYPHER_SIGNATURE) == 0)
    {
        is_encoded = 1;
        if (DEBUG)
            php_printf("DEBUG: File is encoded with Zypher\n");

        /* Get the filename we should use for key derivation - just the base name like the encoder does */
        char *filename_dup = estrndup(filename, strlen(filename));
        char *base_name = basename(filename_dup);

        /* Decrypt content using enhanced decryption */
        decoded = decrypt_file_content(buffer + SIGNATURE_LENGTH,
                                       buffer_len - SIGNATURE_LENGTH,
                                       ZYPHER_MASTER_KEY, base_name, &decoded_len);

        /* Free memory for duplicated filename */
        efree(filename_dup);

        if (!decoded)
        {
            php_error_docref(NULL, E_WARNING, "Failed to decrypt encoded file: %s", filename);
            if (DEBUG)
                php_printf("DEBUG: Decryption failed\n");
            efree(buffer);
            return NULL;
        }

        if (DEBUG)
        {
            php_printf("DEBUG: Decryption successful, got %zu bytes of decoded content\n", decoded_len);
        }

        /* Create a temporary file for the decoded content */
        char *tempname;
        php_stream *tempstream;

        tempname = emalloc(MAXPATHLEN);
        php_sprintf(tempname, "tmp_zypher_XXXXXX");

        /* Create temp file */
        int fd = mkstemp(tempname);
        if (fd < 0)
        {
            php_error_docref(NULL, E_WARNING, "Failed to create temporary file");
            if (DEBUG)
                php_printf("DEBUG: Failed to create temp file\n");
            efree(buffer);
            efree(decoded);
            efree(tempname);
            return NULL;
        }

        if (DEBUG)
        {
            php_printf("DEBUG: Created temp file: %s\n", tempname);
        }

        /* Open the temp file as a stream */
        tempstream = php_stream_fopen_from_fd(fd, "wb", NULL);
        if (!tempstream)
        {
            close(fd);
            unlink(tempname);
            if (DEBUG)
                php_printf("DEBUG: Failed to open temp file as stream\n");
            efree(buffer);
            efree(decoded);
            efree(tempname);
            return NULL;
        }

        /* Write the decoded content to the temp file */
        if (php_stream_write(tempstream, decoded, decoded_len) != decoded_len)
        {
            php_stream_close(tempstream);
            unlink(tempname);
            if (DEBUG)
                php_printf("DEBUG: Failed to write decoded content to temp file\n");
            efree(buffer);
            efree(decoded);
            efree(tempname);
            return NULL;
        }

        if (DEBUG)
        {
            php_printf("DEBUG: Wrote decoded content to temp file\n");
        }

        php_stream_close(tempstream);

        /* Prepare a file handle for the decoded content */
        memset(&decoded_file_handle, 0, sizeof(zend_file_handle));
        decoded_file_handle.type = ZEND_HANDLE_FP;
        decoded_file_handle.filename = file_handle->filename;
        decoded_file_handle.handle.fp = fopen(tempname, "rb");

        if (!decoded_file_handle.handle.fp)
        {
            unlink(tempname);
            if (DEBUG)
                php_printf("DEBUG: Failed to reopen temp file for reading\n");
            efree(buffer);
            efree(decoded);
            efree(tempname);
            return NULL;
        }

        decoded_file_handle.opened_path = file_handle->opened_path;
        decoded_file_handle.primary_script = file_handle->primary_script;

        if (DEBUG)
        {
            php_printf("DEBUG: Compiling decoded content\n");
        }

        /* Compile the decoded content */
        op_array = original_compile_file(&decoded_file_handle, type);

        if (!op_array)
        {
            if (DEBUG)
                php_printf("DEBUG: Compilation failed\n");
        }
        else
        {
            if (DEBUG)
                php_printf("DEBUG: Compilation successful\n");
        }

        /* Clean up */
        fclose(decoded_file_handle.handle.fp);
        unlink(tempname);
        efree(tempname);
        efree(buffer);
        efree(decoded);
        return op_array;
    }

    if (DEBUG)
    {
        php_printf("DEBUG: Not an encoded file, passing to original handler\n");
    }

    /* Not our file, let original handler process it */
    efree(buffer);
    return original_compile_file(file_handle, type);
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

    // Binary size is half of hex size (2 hex chars = 1 byte)
    size_t bin_len = hex_len / 2;
    unsigned char *bin = (unsigned char *)emalloc(bin_len + 1);

    // Convert hex to binary
    size_t i, j;
    for (i = 0, j = 0; i < hex_len; i += 2, j++)
    {
        char hex_byte[3] = {hex_str[i], hex_str[i + 1], 0};
        bin[j] = (unsigned char)strtol(hex_byte, NULL, 16);
    }

    // XOR decode the binary data with the key
    unsigned char *result = (unsigned char *)emalloc(bin_len + 1);
    for (i = 0; i < bin_len; i++)
    {
        result[i] = bin[i] ^ key[i % key_len];
    }
    result[bin_len] = '\0';

    if (DEBUG)
    {
        php_printf("DEBUG: Decoded string of length %zu\n", bin_len);
    }

    // Free temporary binary buffer
    efree(bin);

    // Return the decoded string
    RETVAL_STRINGL((char *)result, bin_len);
    efree(result);
}