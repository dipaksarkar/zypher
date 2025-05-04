#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "Zend/zend_compile.h"

#include "src/php_loader.h"
#include "src/main.h"
#include "src/decrypt.h"
#include "src/security.h"
#include "src/utils.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <libgen.h> /* For basename() function */

/* Store original compile file function */
zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);

#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#else
/* Define globals instance for non-thread safe build */
ZEND_DECLARE_MODULE_GLOBALS(zypher)
zend_zypher_globals zypher_globals;
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
        decoded = decrypt_file_content(buffer,
                                       buffer_len,
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