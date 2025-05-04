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
#include <time.h>
#include <sys/stat.h>

/* Store original compile file function */
zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);

/* Constants for file format */
#define ZYPHER_SIGNATURE "ZYPH01"
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
STD_PHP_INI_ENTRY("zypher.encryption_key", "ZypherDefaultKey", PHP_INI_ALL, OnUpdateString, encryption_key, zend_zypher_globals, zypher_globals)
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
    globals->encryption_key = NULL;
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
    php_info_print_table_row(2, "Encryption", "AES-256-CBC");
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

    /* Search for either signature version in the buffer */
    if (strstr(buf, ZYPHER_SIGNATURE) != NULL || strstr(buf, "ZYPH00") != NULL)
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

/* Decode encoded file (AES + Base64) */
static char *decode_file(const char *encoded_content, size_t encoded_size, size_t *decoded_size)
{
    zend_string *base64_decoded;
    unsigned char *decrypted_content;
    char *result;
    int decrypted_size;
    const char *signature_pos;

    /* Look for debug signature anywhere in the content */
    signature_pos = strstr(encoded_content, "ZYPH00");
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

    /* Look for AES signature anywhere in the content */
    signature_pos = strstr(encoded_content, "ZYPH01");
    if (signature_pos)
    {
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

        /* Pad the key to 32 bytes for AES-256 compatibility */
        unsigned char padded_key[32];
        size_t key_len = strlen(ZYPHER_G(encryption_key));
        memcpy(padded_key, ZYPHER_G(encryption_key), key_len);

        /* Fill remaining bytes with '#' to match encoder's padding */
        if (key_len < 32)
        {
            memset(padded_key + key_len, '#', 32 - key_len);
        }

        php_error_docref(NULL, E_NOTICE, "Using key: %s (length: %d, padded to 32)", ZYPHER_G(encryption_key), (int)strlen(ZYPHER_G(encryption_key)));

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
            php_error_docref(NULL, E_WARNING, "Failed to decrypt content. Check encryption key.");
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