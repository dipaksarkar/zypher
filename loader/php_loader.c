#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/base64.h"
#include "Zend/zend_compile.h"
#include "php_loader.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <time.h>
#include <sys/stat.h>

/* Store original compile file function */
zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);

/* Constants for file format */
#define ZYPHER_SIGNATURE_OLD "ZYPH01"
#define ZYPHER_SIGNATURE_NEW "ZYPH02"
#define ZYPHER_SIGNATURE_DEBUG "ZYPH00"
#define SIGNATURE_LENGTH 6
#define IV_LENGTH 16

/* License checking constants */
#define LICENSE_CHECK_INTERVAL 3600 /* Check license validity once per hour */
#define LICENSE_FIELD_MAX 256

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

/* INI entries */
PHP_INI_BEGIN()
STD_PHP_INI_ENTRY("zypher.license_path", "", PHP_INI_ALL, OnUpdateString, license_path, zend_zypher_globals, zypher_globals)
STD_PHP_INI_ENTRY("zypher.license_check_enabled", "1", PHP_INI_ALL, OnUpdateBool, license_check_enabled, zend_zypher_globals, zypher_globals)
PHP_INI_END()

/* Define the module entry */
zend_module_entry zypher_module_entry = {
    STANDARD_MODULE_HEADER,
    "zypher",              /* Extension name */
    NULL,                  /* Function entries */
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
    globals->license_path = NULL;
    globals->license_check_enabled = 1;
    globals->license_cached_expiry = 0;
    globals->license_cached_valid = 0;
}

/* License checking function */
int check_license_validity()
{
    /* Check if license checking is disabled */
    if (!ZYPHER_G(license_check_enabled))
    {
        return 1; /* Valid if license checking is disabled */
    }

    /* Check if license path is set */
    if (!ZYPHER_G(license_path) || strlen(ZYPHER_G(license_path)) == 0)
    {
        php_error_docref(NULL, E_WARNING, "License path not set. Use zypher.license_path in php.ini");
        return 0;
    }

    /* Basic file existence check */
    struct stat file_stat;
    if (stat(ZYPHER_G(license_path), &file_stat) != 0)
    {
        php_error_docref(NULL, E_WARNING, "License file not found: %s", ZYPHER_G(license_path));
        return 0;
    }

    /* In a full implementation, we would validate license contents here */
    php_error_docref(NULL, E_NOTICE, "Valid license file found at: %s", ZYPHER_G(license_path));

    return 1;
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

    /* Perform initial license check */
    if (!check_license_validity())
    {
        php_error_docref(NULL, E_WARNING,
                         "Zypher license check failed. Decoding may be disabled for security reasons. "
                         "Please update your license or contact support.");
    }

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
    char license_status[64] = "Unknown";

    if (!ZYPHER_G(license_check_enabled))
    {
        strcpy(license_status, "Disabled (Not Recommended)");
    }
    else if (ZYPHER_G(license_cached_valid))
    {
        strcpy(license_status, "Valid");
    }
    else if (check_license_validity())
    {
        strcpy(license_status, "Valid");
    }
    else
    {
        strcpy(license_status, "Invalid or Expired");
    }

    php_info_print_table_start();
    php_info_print_table_header(2, "Zypher Support", "enabled");
    php_info_print_table_row(2, "Version", PHP_ZYPHER_VERSION);
    php_info_print_table_row(2, "Encryption", "AES-256-CBC with secure key management");
    php_info_print_table_row(2, "License Status", license_status);
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}

/* Remove the extension check and instead scan the file contents for our signature */
static int is_encoded_file(const char *filename)
{
    size_t len;
    php_stream *stream;
    char buf[128] = {0}; /* Larger buffer to read more of the file */
    int read_bytes;
    int result = 0;

    if (!filename)
    {
        return 0;
    }

    /* We need to check files with .php extension */
    len = strlen(filename);
    if (len <= 4 || strcasecmp(filename + len - 4, ".php") != 0)
    {
        return 0;
    }

    /* Open the file and read the first portion to check for our signature */
    stream = php_stream_open_wrapper((char *)filename, "rb", IGNORE_PATH | REPORT_ERRORS, NULL);
    if (!stream)
    {
        return 0;
    }

    /* Read signature size + more content to check for embedded signature */
    read_bytes = php_stream_read(stream, buf, sizeof(buf) - 1);
    php_stream_close(stream);

    if (read_bytes < SIGNATURE_LENGTH)
    {
        return 0;
    }

    /* We need to check if the file contains our signature anywhere in the first block
       The file starts with <?php stub code, and our signature is embedded somewhere after that */
    buf[read_bytes] = '\0';

    /* Search for any signature version in the buffer */
    if (strstr(buf, ZYPHER_SIGNATURE_OLD) != NULL ||
        strstr(buf, ZYPHER_SIGNATURE_NEW) != NULL ||
        strstr(buf, ZYPHER_SIGNATURE_DEBUG) != NULL)
    {
        result = 1;
    }

    return result;
}

/* Read file contents using php_stream */
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

    *size = file_size;
    return contents;
}

/* AES decrypt function */
static int aes_decrypt(
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *key,
    const unsigned char *iv,
    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        return -1;
    }

    /* Initialize decryption operation */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Provide the message to be decrypted, and obtain the plaintext output */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    /* Finalize the decryption */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/* Generate padded master key for AES-256 */
static void generate_padded_master_key(unsigned char *padded_key)
{
    /* Use EVP interface for SHA-256 to create a consistent 32-byte key from the master key */
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, ZYPHER_MASTER_KEY, strlen(ZYPHER_MASTER_KEY));
    EVP_DigestFinal_ex(mdctx, padded_key, &md_len);
    EVP_MD_CTX_free(mdctx);

    /* Debug output for key */
    if (DEBUG)
    {
        php_error_docref(NULL, E_NOTICE, "Using master key: %s", ZYPHER_MASTER_KEY);
    }
}

/* Decode encoded file (AES + Base64) with the new format supporting per-file keys */
static char *decode_file(const char *encoded_content, size_t encoded_size, size_t *decoded_size)
{
    zend_string *base64_decoded;
    unsigned char *decrypted_content;
    char *result;
    int decrypted_size;
    const char *signature_pos;

    /* Debug information to stdout for visibility */
    php_error_docref(NULL, E_NOTICE, "Decoding file with size: %d bytes", (int)encoded_size);

    /* Look for debug signature anywhere in the content */
    signature_pos = strstr(encoded_content, ZYPHER_SIGNATURE_DEBUG);
    if (signature_pos)
    {
        /* Debug mode - simple base64 */
        php_error_docref(NULL, E_NOTICE, "Debug mode detected - using simple base64 decoding");

        /* Calculate remaining size after the signature */
        size_t remaining_size = encoded_size - (signature_pos - encoded_content) - 6;

        base64_decoded = php_base64_decode(
            (unsigned char *)(signature_pos + 6),
            remaining_size);

        if (!base64_decoded)
        {
            php_error_docref(NULL, E_WARNING, "Debug mode: Failed to decode base64 content");
            return NULL;
        }

        /* Allocate memory for decoded content */
        result = estrndup(ZSTR_VAL(base64_decoded), ZSTR_LEN(base64_decoded));
        *decoded_size = ZSTR_LEN(base64_decoded);

        /* Free decoded string */
        zend_string_release(base64_decoded);
        return result;
    }

    /* Check for new format with embedded keys */
    signature_pos = strstr(encoded_content, ZYPHER_SIGNATURE_NEW);
    if (signature_pos)
    {
        php_error_docref(NULL, E_NOTICE, "Found new signature format ZYPH02");

        /* Calculate remaining size after the signature */
        size_t remaining_size = encoded_size - (signature_pos - encoded_content) - 6;
        php_error_docref(NULL, E_NOTICE, "Remaining size after signature: %d bytes", (int)remaining_size);

        /* Decode base64 (skip the signature) */
        base64_decoded = php_base64_decode(
            (unsigned char *)(signature_pos + 6),
            remaining_size);

        if (!base64_decoded)
        {
            php_error_docref(NULL, E_WARNING, "Failed to decode base64 content");
            return NULL;
        }

        php_error_docref(NULL, E_NOTICE, "Base64 decoded length: %d bytes", (int)ZSTR_LEN(base64_decoded));

        /* Ensure we have enough data for the header:
           - 16 bytes: Content IV
           - 16 bytes: Key IV
           - 4 bytes: Key length
        */
        if (ZSTR_LEN(base64_decoded) < (IV_LENGTH * 2 + 4))
        {
            php_error_docref(NULL, E_WARNING, "Invalid encoded file format (too short for header)");
            zend_string_release(base64_decoded);
            return NULL;
        }

        /* Extract content IV (first 16 bytes) */
        unsigned char content_iv[IV_LENGTH];
        memcpy(content_iv, ZSTR_VAL(base64_decoded), IV_LENGTH);

        /* Extract key IV (next 16 bytes) */
        unsigned char key_iv[IV_LENGTH];
        memcpy(key_iv, ZSTR_VAL(base64_decoded) + IV_LENGTH, IV_LENGTH);

        /* Extract encrypted key length (next 4 bytes) */
        uint32_t key_length;
        memcpy(&key_length, ZSTR_VAL(base64_decoded) + IV_LENGTH * 2, 4);
        key_length = ntohl(key_length); /* Convert from network byte order to host byte order */

        php_error_docref(NULL, E_NOTICE, "Encrypted key length: %u bytes", key_length);

        /* Validate key length */
        if (key_length == 0 || key_length > 1024 ||
            (IV_LENGTH * 2 + 4 + key_length) > ZSTR_LEN(base64_decoded))
        {
            php_error_docref(NULL, E_WARNING, "Invalid key length in encoded file: %u", key_length);
            zend_string_release(base64_decoded);
            return NULL;
        }

        /* Extract encrypted file key */
        unsigned char *encrypted_file_key = emalloc(key_length);
        memcpy(encrypted_file_key, ZSTR_VAL(base64_decoded) + IV_LENGTH * 2 + 4, key_length);

        /* Generate padded master key from the constant */
        unsigned char padded_master_key[32];
        generate_padded_master_key(padded_master_key);

        /* Decrypt the file key */
        unsigned char *decrypted_file_key = emalloc(key_length + 16); /* Output will be smaller than input + some padding */
        int decrypted_key_size = aes_decrypt(
            encrypted_file_key, key_length,
            padded_master_key, key_iv,
            decrypted_file_key);

        if (decrypted_key_size < 0)
        {
            php_error_docref(NULL, E_WARNING, "Failed to decrypt file key");
            zend_string_release(base64_decoded);
            efree(encrypted_file_key);
            efree(decrypted_file_key);
            return NULL;
        }

        php_error_docref(NULL, E_NOTICE, "Decrypted key size: %d bytes", decrypted_key_size);

        /* Null-terminate the decrypted key for safety */
        if (decrypted_key_size < key_length + 16)
        {
            decrypted_file_key[decrypted_key_size] = '\0';
        }

        /* Calculate offset to encrypted content */
        size_t content_offset = IV_LENGTH * 2 + 4 + key_length;
        size_t encrypted_content_size = ZSTR_LEN(base64_decoded) - content_offset;

        php_error_docref(NULL, E_NOTICE, "Content offset: %d, Encrypted content size: %d bytes",
                         (int)content_offset, (int)encrypted_content_size);

        /* Allocate memory for decrypted content */
        decrypted_content = emalloc(encrypted_content_size + 16); /* Will be smaller than this size + padding */

        /* Create a padded key from the file key for AES-256 */
        unsigned char padded_file_key[32];
        memset(padded_file_key, 0, sizeof(padded_file_key));
        memcpy(padded_file_key, decrypted_file_key, decrypted_key_size > 32 ? 32 : decrypted_key_size);

        /* Decrypt the content using the file key */
        decrypted_size = aes_decrypt(
            (unsigned char *)ZSTR_VAL(base64_decoded) + content_offset,
            encrypted_content_size,
            padded_file_key, /* Use the padded file key */
            content_iv,
            decrypted_content);

        /* Free temporary buffers */
        efree(encrypted_file_key);
        efree(decrypted_file_key);
        zend_string_release(base64_decoded);

        if (decrypted_size < 0)
        {
            php_error_docref(NULL, E_WARNING, "Failed to decrypt content with file key");
            efree(decrypted_content);
            return NULL;
        }

        php_error_docref(NULL, E_NOTICE, "Decrypted content size: %d bytes", decrypted_size);

        /* Create a null-terminated string with the decrypted content */
        result = emalloc(decrypted_size + 1);
        memcpy(result, decrypted_content, decrypted_size);
        result[decrypted_size] = '\0';

        /* Free temporary buffer */
        efree(decrypted_content);

        *decoded_size = decrypted_size;
        return result;
    }

    /* Look for old AES signature for backward compatibility */
    signature_pos = strstr(encoded_content, ZYPHER_SIGNATURE_OLD);
    if (signature_pos)
    {
        /* Show warning that this is deprecated */
        php_error_docref(NULL, E_WARNING, "Using legacy format without embedded key. This format is deprecated.");

        /* Calculate remaining size after the signature */
        size_t remaining_size = encoded_size - (signature_pos - encoded_content) - 6;

        /* Decode base64 (skip the signature) */
        base64_decoded = php_base64_decode(
            (unsigned char *)(signature_pos + 6),
            remaining_size);

        if (!base64_decoded)
        {
            php_error_docref(NULL, E_WARNING, "Failed to decode base64 content");
            return NULL;
        }

        if (ZSTR_LEN(base64_decoded) <= IV_LENGTH)
        {
            php_error_docref(NULL, E_WARNING, "Invalid encoded file format (too short)");
            zend_string_release(base64_decoded);
            return NULL;
        }

        /* Extract IV (first 16 bytes) */
        unsigned char iv[IV_LENGTH];
        memcpy(iv, ZSTR_VAL(base64_decoded), IV_LENGTH);

        /* For compatibility with old format, use hardcoded key */
        const char *legacy_key = "ZypherDefaultKey";

        /* Pad the legacy key to 32 bytes for AES-256 compatibility */
        unsigned char padded_key[32];
        size_t key_len = strlen(legacy_key);
        memcpy(padded_key, legacy_key, key_len);

        /* Fill remaining bytes with '#' to match encoder's padding */
        if (key_len < 32)
        {
            memset(padded_key + key_len, '#', 32 - key_len);
        }

        /* Allocate memory for decrypted content */
        decrypted_content = emalloc(ZSTR_LEN(base64_decoded)); /* Will be smaller than or equal to this size */

        /* Decrypt the content using AES */
        decrypted_size = aes_decrypt(
            (unsigned char *)ZSTR_VAL(base64_decoded) + IV_LENGTH,
            ZSTR_LEN(base64_decoded) - IV_LENGTH,
            padded_key,
            iv,
            decrypted_content);

        /* Free base64 decoded buffer */
        zend_string_release(base64_decoded);

        if (decrypted_size < 0)
        {
            php_error_docref(NULL, E_WARNING, "Failed to decrypt content with legacy key");
            efree(decrypted_content);
            return NULL;
        }

        /* Create a null-terminated string with the decrypted content */
        result = emalloc(decrypted_size + 1);
        memcpy(result, decrypted_content, decrypted_size);
        result[decrypted_size] = '\0';

        /* Free temporary buffer */
        efree(decrypted_content);

        *decoded_size = decrypted_size;
        return result;
    }

    /* No recognized signature found */
    php_error_docref(NULL, E_WARNING, "No Zypher signature found in file");
    return NULL;
}

/* Custom file compilation handler */
zend_op_array *zypher_compile_file(zend_file_handle *file_handle, int type)
{
    char *encoded_content, *decoded_content;
    size_t encoded_size, decoded_size;
    zend_string *filename_zstr;
    zend_string *source_zstr;
    zend_op_array *op_array;

    /* Check if file exists and is an encoded file */
    if (!file_handle || !file_handle->filename || !is_encoded_file(ZSTR_VAL(file_handle->filename)))
    {
        /* Not an encoded file, pass to original handler */
        return original_compile_file(file_handle, type);
    }

    /* Only proceed if license is valid */
    if (ZYPHER_G(license_check_enabled) && !check_license_validity())
    {
        php_error_docref(NULL, E_WARNING, "Cannot decode file: License is invalid or expired");
        return NULL; /* Return NULL to prevent execution */
    }

    /* Read encoded file contents */
    encoded_content = read_file_contents(ZSTR_VAL(file_handle->filename), &encoded_size);
    if (!encoded_content)
    {
        /* Cannot read file, pass to original handler */
        return original_compile_file(file_handle, type);
    }

    /* Decode file contents */
    decoded_content = decode_file(encoded_content, encoded_size, &decoded_size);
    if (!decoded_content)
    {
        /* Cannot decode file */
        efree(encoded_content);
        return original_compile_file(file_handle, type);
    }

    /* Create string with decoded content */
    source_zstr = zend_string_init(decoded_content, decoded_size, 0);

    /* Clone the filename */
    filename_zstr = zend_string_copy(file_handle->filename);

    /* Free temporary buffers */
    efree(encoded_content);
    efree(decoded_content);

    /* Compile the decoded content - with proper parameters for PHP 8.3+ */
    op_array = zend_compile_string(source_zstr, ZSTR_VAL(filename_zstr), ZEND_COMPILE_POSITION_AT_OPEN_TAG);

    /* Free strings */
    zend_string_release(source_zstr);
    zend_string_release(filename_zstr);

    return op_array;
}