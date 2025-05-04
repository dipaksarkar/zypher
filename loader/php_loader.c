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

/* Store original compile file function */
zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);

/* Constants for file format */
#define ZYPHER_SIGNATURE "ZYPH01"
#define SIGNATURE_LENGTH 6
#define IV_LENGTH 16

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

PHP_INI_BEGIN()
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
    // No globals needed
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

/* Decrypt encoded file content */
static char *decrypt_file_content(const char *encoded_content, size_t encoded_length,
                                  const char *key, size_t *out_length)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    unsigned char iv[IV_LENGTH];
    char *decrypted = NULL;
    int outlen, tmplen;
    zend_string *decoded_str;

    /* Base64 decode first - Updated for new API */
    decoded_str = php_base64_decode((const unsigned char *)encoded_content, encoded_length);
    if (!decoded_str)
    {
        return NULL;
    }

    /* Check if we have enough decoded data for IV */
    if (ZSTR_LEN(decoded_str) <= IV_LENGTH)
    {
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract IV from the first 16 bytes */
    memcpy(iv, ZSTR_VAL(decoded_str), IV_LENGTH);

    /* Create decryption context */
    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_aes_256_cbc();

    /* Initialize decryption operation */
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char *)key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Decrypt the content */
    decrypted = emalloc(ZSTR_LEN(decoded_str));

    if (!EVP_DecryptUpdate(ctx, (unsigned char *)decrypted, &outlen,
                           (unsigned char *)ZSTR_VAL(decoded_str) + IV_LENGTH,
                           ZSTR_LEN(decoded_str) - IV_LENGTH))
    {
        EVP_CIPHER_CTX_free(ctx);
        zend_string_release(decoded_str);
        efree(decrypted);
        return NULL;
    }

    /* Finalize decryption */
    if (!EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted + outlen, &tmplen))
    {
        EVP_CIPHER_CTX_free(ctx);
        zend_string_release(decoded_str);
        efree(decrypted);
        return NULL;
    }

    /* Set output length */
    if (out_length)
    {
        *out_length = outlen + tmplen;
    }

    /* Null terminate the decrypted content */
    decrypted[outlen + tmplen] = '\0';

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
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
    char file_key[33] = {0}; /* 32 bytes + null */
    const char *filename;

    /* Skip if no file or already processed */
    if (!file_handle || !file_handle->filename)
    {
        return original_compile_file(file_handle, type);
    }

    /* Handle zend_string filename in PHP 8.x */
    filename = ZSTR_VAL(file_handle->filename);

    /* Read the file contents */
    buffer = read_file_contents(filename, &buffer_len);
    if (!buffer || buffer_len < SIGNATURE_LENGTH)
    {
        /* Not our file or couldn't read it */
        if (buffer)
        {
            efree(buffer);
        }
        return original_compile_file(file_handle, type);
    }

    /* Check for our signature */
    memcpy(signature, buffer, SIGNATURE_LENGTH);
    signature[SIGNATURE_LENGTH] = '\0';

    if (strcmp(signature, ZYPHER_SIGNATURE) == 0)
    {
        is_encoded = 1;

        /* Extract file-specific key (in a real implementation, this would be better secured) */
        SHA256((const unsigned char *)ZYPHER_MASTER_KEY, strlen(ZYPHER_MASTER_KEY), (unsigned char *)file_key);
        file_key[32] = '\0';

        /* Decrypt content */
        decoded = decrypt_file_content(buffer + SIGNATURE_LENGTH,
                                       buffer_len - SIGNATURE_LENGTH,
                                       file_key, &decoded_len);

        if (!decoded)
        {
            php_error_docref(NULL, E_WARNING, "Failed to decrypt encoded file: %s", filename);
            efree(buffer);
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
            efree(buffer);
            efree(decoded);
            efree(tempname);
            return NULL;
        }

        /* Open the temp file as a stream */
        tempstream = php_stream_fopen_from_fd(fd, "wb", NULL);
        if (!tempstream)
        {
            close(fd);
            unlink(tempname);
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
            efree(buffer);
            efree(decoded);
            efree(tempname);
            return NULL;
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
            efree(buffer);
            efree(decoded);
            efree(tempname);
            return NULL;
        }

        decoded_file_handle.opened_path = file_handle->opened_path;
        decoded_file_handle.primary_script = file_handle->primary_script;

        /* Compile the decoded content */
        op_array = original_compile_file(&decoded_file_handle, type);

        /* Clean up */
        fclose(decoded_file_handle.handle.fp);
        unlink(tempname);
        efree(tempname);
        efree(buffer);
        efree(decoded);
        return op_array;
    }

    /* Not our file, let original handler process it */
    efree(buffer);
    return original_compile_file(file_handle, type);
}