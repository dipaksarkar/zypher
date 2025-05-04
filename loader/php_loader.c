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

/* Override the DEBUG definition from php_loader.h with our runtime version */
#undef DEBUG
#define DEBUG (ZYPHER_G(debug_mode) && php_get_module_initialized())

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
    globals->debug_mode = 0; /* Initialize debug_mode to 0 */
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

    // Create a salt based on filename (matching encoder implementation)
    snprintf(salt, sizeof(salt), "ZypherSalt-%s", filename);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // Initial HMAC
    HMAC(EVP_sha256(), master_key, strlen(master_key),
         (unsigned char *)salt, strlen(salt), hash, NULL);

    // Multiple iterations for key strengthening
    for (int i = 0; i < iterations && i < MAX_KEY_ITERATIONS; i++)
    {
        // Add iteration counter to salt (matching encoder implementation)
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
        // Add iteration counter to match encode.php implementation
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
int verify_content_integrity(const char *content, size_t content_len, const char *checksum)
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
    unsigned char key_iv[IV_LENGTH]; /* For new format with separate IVs */
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

    /* Debug output */
    if (DEBUG)
    {
        php_printf("DEBUG: Decrypting content of length %zu\n", encoded_length);
    }

    /* Check for Zypher signature */
    if (encoded_length < SIGNATURE_LENGTH || strncmp(encoded_content, ZYPHER_SIGNATURE, SIGNATURE_LENGTH) != 0)
    {
        if (DEBUG)
            php_printf("DEBUG: Invalid signature\n");
        return NULL;
    }

    /* Base64 decode the content after signature */
    decoded_str = php_base64_decode(
        (const unsigned char *)encoded_content + SIGNATURE_LENGTH,
        encoded_length - SIGNATURE_LENGTH);

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

    /* Handle byte rotation if present (enhanced format) */
    char *rotated_content = NULL;

    /* Check if first byte value suggests byte rotation (+7) */
    if (ZSTR_LEN(decoded_str) > 0)
    {
        /* Simple heuristic: check if first byte is likely version byte (1) rotated by +7 */
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
                rotated_content[i] = (char)((unsigned char)(ZSTR_VAL(decoded_str)[i] - 7) & 0xFF);
            }
            rotated_content[ZSTR_LEN(decoded_str)] = '\0';

            /* Replace decoded_str with rotated content for further processing */
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
            *out_length = ZSTR_LEN(decoded_str);

        zend_string_release(decoded_str);
        return decrypted;
    }

    /* Parse the enhanced format */
    pos = 0;
    unsigned char *data = (unsigned char *)ZSTR_VAL(decoded_str);
    size_t data_len = ZSTR_LEN(decoded_str);

    /* Make sure we have enough data for the version byte */
    if (data_len < pos + 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for version byte\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract format version */
    format_version = data[pos++];

    if (DEBUG)
    {
        php_printf("DEBUG: Format version: %d\n", format_version);
    }

    /* Verify expected format version */
    if (format_version != ZYPHER_FORMAT_VERSION)
    {
        if (DEBUG)
            php_printf("DEBUG: Unsupported format version %d (expected %d)\n",
                       format_version, ZYPHER_FORMAT_VERSION);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Check for timestamp */
    if (data_len < pos + 4)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for timestamp\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract timestamp (big endian) */
    timestamp = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
    pos += 4;

    if (DEBUG)
    {
        php_printf("DEBUG: Timestamp: %u\n", timestamp);
    }

    /* Verify license based on timestamp */
    int license_error = zypher_verify_license(NULL, timestamp);
    if (license_error != ZYPHER_ERR_NONE)
    {
        if (DEBUG)
        {
            switch (license_error)
            {
            case ZYPHER_ERR_EXPIRED:
                php_printf("DEBUG: License expired\n");
                break;
            case ZYPHER_ERR_DOMAIN:
                php_printf("DEBUG: Domain mismatch\n");
                break;
            default:
                php_printf("DEBUG: License error %d\n", license_error);
                break;
            }
        }
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract content IV */
    if (data_len < pos + IV_LENGTH)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for content IV\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    memcpy(iv, data + pos, IV_LENGTH);
    pos += IV_LENGTH;

    if (DEBUG)
    {
        char hex_iv[IV_LENGTH * 2 + 1];
        for (int i = 0; i < IV_LENGTH; i++)
            sprintf(hex_iv + i * 2, "%02x", iv[i]);
        hex_iv[IV_LENGTH * 2] = '\0';
        php_printf("DEBUG: Content IV: %s\n", hex_iv);
    }

    /* Extract key IV */
    if (data_len < pos + IV_LENGTH)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for key IV\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    memcpy(key_iv, data + pos, IV_LENGTH);
    pos += IV_LENGTH;

    if (DEBUG)
    {
        char hex_key_iv[IV_LENGTH * 2 + 1];
        for (int i = 0; i < IV_LENGTH; i++)
            sprintf(hex_key_iv + i * 2, "%02x", key_iv[i]);
        hex_key_iv[IV_LENGTH * 2] = '\0';
        php_printf("DEBUG: Key IV: %s\n", hex_key_iv);
    }

    /* Extract key length */
    if (data_len < pos + 4)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for key length\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    key_length = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
    pos += 4;

    if (DEBUG)
    {
        php_printf("DEBUG: Key length: %u\n", key_length);
    }

    /* Extract encrypted file key */
    if (data_len < pos + key_length)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for encrypted file key\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    encrypted_file_key = emalloc(key_length + 1);
    memcpy(encrypted_file_key, data + pos, key_length);
    encrypted_file_key[key_length] = '\0';
    pos += key_length;

    /* Extract original filename length */
    if (data_len < pos + 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for filename length\n");
        efree(encrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    filename_length = data[pos++];

    if (DEBUG)
    {
        php_printf("DEBUG: Original filename length: %u\n", filename_length);
    }

    /* Extract original filename - important for key derivation */
    if (data_len < pos + filename_length)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for original filename\n");
        efree(encrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    orig_filename = emalloc(filename_length + 1);
    memcpy(orig_filename, data + pos, filename_length);
    orig_filename[filename_length] = '\0';
    pos += filename_length;

    if (DEBUG)
    {
        php_printf("DEBUG: Original filename: %s\n", orig_filename);
    }

    /* The rest is encrypted content */
    size_t encrypted_content_length = data_len - pos;
    if (encrypted_content_length == 0)
    {
        if (DEBUG)
            php_printf("DEBUG: No encrypted content\n");
        efree(encrypted_file_key);
        efree(orig_filename);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Derive master key from filename */
    char derived_key[65];

    /* Use original filename for key derivation, not the current one */
    zypher_derive_key(master_key, orig_filename, derived_key, 1000);

    if (DEBUG)
    {
        php_printf("DEBUG: Derived master key: %s\n", derived_key);
    }

    /* Create OpenSSL cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to create cipher context\n");
        efree(encrypted_file_key);
        efree(orig_filename);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Select AES-256-CBC cipher */
    cipher = EVP_aes_256_cbc();

    /* Decrypt the file key with derived master key */
    char *decrypted_file_key = emalloc(key_length + EVP_MAX_BLOCK_LENGTH);

    /* Initialize decryption process */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL,
                           (unsigned char *)derived_key, key_iv) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Perform decryption */
    if (EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_file_key, &outlen,
                          (unsigned char *)encrypted_file_key, key_length) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to decrypt file key\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Finalize decryption */
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted_file_key + outlen, &tmplen) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to finalize key decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    outlen += tmplen;
    decrypted_file_key[outlen] = '\0';

    if (DEBUG)
    {
        php_printf("DEBUG: Decrypted file key: %s (length: %d)\n", decrypted_file_key, outlen);
    }

    /* Now decrypt actual file content using the decrypted file key */
    EVP_CIPHER_CTX_reset(ctx);

    /* Initialize encryption with file key and content IV */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL,
                           (unsigned char *)decrypted_file_key, iv) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to initialize content decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Allocate memory for decrypted content */
    decrypted = emalloc(encrypted_content_length + EVP_MAX_BLOCK_LENGTH + 1);

    /* Perform decryption */
    if (EVP_DecryptUpdate(ctx, (unsigned char *)decrypted, &outlen,
                          (unsigned char *)(data + pos), encrypted_content_length) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to decrypt content\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        efree(decrypted_file_key);
        efree(decrypted);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Finalize decryption */
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted + outlen, &tmplen) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to finalize content decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        efree(decrypted_file_key);
        efree(decrypted);
        zend_string_release(decoded_str);
        return NULL;
    }

    outlen += tmplen;
    decrypted[outlen] = '\0';

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    efree(encrypted_file_key);
    efree(decrypted_file_key);

    /* Extract checksum from the beginning of decrypted data */
    memcpy(extracted_checksum, decrypted, 32);
    extracted_checksum[32] = '\0';

    /* Move the actual PHP content to the beginning */
    memmove(decrypted, decrypted + 32, outlen - 32 + 1);
    outlen -= 32;

    if (DEBUG)
    {
        php_printf("DEBUG: Extracted checksum: %s\n", extracted_checksum);
    }

    /* Verify content integrity with checksum */
    if (verify_content_integrity(decrypted, outlen, extracted_checksum) != ZYPHER_ERR_NONE)
    {
        if (DEBUG)
            php_printf("DEBUG: Content integrity check failed\n");
        efree(orig_filename);
        efree(decrypted);
        zend_string_release(decoded_str);
        return NULL;
    }

    if (DEBUG)
    {
        php_printf("DEBUG: Content integrity verified!\n");
    }

    /* Set output length */
    if (out_length)
        *out_length = outlen;

    efree(orig_filename);
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

    /* Check for direct signature at start of file */
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
            php_printf("DEBUG: File is directly encoded with Zypher\n");
    }

    if (is_encoded)
    {
        /* Get the filename we should use for key derivation - just the base name like the encoder does */
        char *filename_dup = estrndup(filename, strlen(filename));
        char *base_name = basename(filename_dup);

        /* Decrypt content using enhanced decryption */
        decoded = decrypt_file_content(buffer + SIGNATURE_LENGTH,
                                       buffer_len - SIGNATURE_LENGTH,
                                       ZYPHER_MASTER_KEY, base_name, &decoded_len);

        /* Free memory for duplicated filename and buffer */
        efree(filename_dup);
        efree(buffer);

        if (!decoded)
        {
            php_error_docref(NULL, E_WARNING, "Failed to decrypt encoded file: %s", filename);
            if (DEBUG)
                php_printf("DEBUG: Decryption failed\n");
            return NULL;
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
    bin[bin_len] = '\0';

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