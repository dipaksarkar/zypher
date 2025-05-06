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

/* Add zend extension entry for loading as zend_extension */
#ifndef ZEND_EXT_API
#define ZEND_EXT_API ZEND_DLEXPORT
#endif

/* Zend extension function declarations need to be before they're used */
static int zypher_startup(zend_extension *extension)
{
    return zend_startup_module(&zypher_module_entry);
}

static void zypher_shutdown(zend_extension *extension)
{
    /* Nothing to do here, the module shutdown handle will be called */
}

/* Register as a Zend extension */
zend_extension_version_info extension_version_info = {
    ZEND_EXTENSION_API_NO,
    ZEND_EXTENSION_BUILD_ID};

/* Define Zend extension entry */
ZEND_DLEXPORT zend_extension zend_extension_entry = {
    "Zypher PHP Loader",
    PHP_ZYPHER_VERSION,
    "Zypher Team",
    "https://www.zypher.com/",
    "Copyright (c) Zypher",
    zypher_startup,  /* Startup */
    zypher_shutdown, /* Shutdown */
    NULL,            /* Activate */
    NULL,            /* Deactivate */
    NULL,            /* Message handler */
    NULL,            /* Op Array Handler */
    NULL,            /* Statement Handler */
    NULL,            /* Fcall Begin Handler */
    NULL,            /* Fcall End Handler */
    NULL,            /* Op Array Constructor */
    NULL,            /* Op Array Destructor */
    STANDARD_ZEND_EXTENSION_PROPERTIES};

/* Init globals */
static void php_zypher_init_globals(zend_zypher_globals *globals)
{
    globals->license_domain = NULL;
    globals->license_expiry = 0;
    globals->self_healing = 0;
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

    if (DEBUG)
    {
        php_printf("Zypher PHP Loader v%s initialized (Debug mode is %s)\n",
                   PHP_ZYPHER_VERSION,
                   DEBUG ? "ON" : "OFF");
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
    php_info_print_table_start();
    php_info_print_table_header(2, "Zypher Support", "enabled");
    php_info_print_table_row(2, "Version", PHP_ZYPHER_VERSION);
    php_info_print_table_row(2, "OpenSSL Support", "enabled");
    php_info_print_table_row(2, "File Format", "encrypted (AES-256-CBC)");
    php_info_print_table_row(2, "Anti-debugging", ZYPHER_DEBUGGER_PROTECTION ? "enabled (hardcoded)" : "disabled");
    php_info_print_table_row(2, "Advanced Obfuscation", "enabled");
    php_info_print_table_row(2, "Debug Mode", DEBUG ? "enabled" : "disabled");
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
        php_printf("DEBUG: File signature: %.10s... (expected: %s)\n", buffer, ZYPHER_SIGNATURE);
    }

    /* Check if the file is encoded by looking for the signature anywhere in the first few KB */
    if (strcmp(signature, ZYPHER_SIGNATURE) == 0)
    {
        is_encoded = 1;
        if (DEBUG)
            php_printf("DEBUG: File is directly encoded with Zypher\n");
    }
    else
    {
        /* Look for signature within the first 1KB in case it follows PHP comments or whitespace */
        size_t search_len = buffer_len > 1024 ? 1024 : buffer_len;
        for (size_t i = 0; i <= search_len - SIGNATURE_LENGTH; i++)
        {
            if (memcmp(buffer + i, ZYPHER_SIGNATURE, SIGNATURE_LENGTH) == 0)
            {
                is_encoded = 1;
                if (DEBUG)
                {
                    php_printf("DEBUG: Found Zypher signature at offset %zu\n", i);

                    /* Add debug output to show characters around the signature */
                    php_printf("DEBUG: Signature context: '");
                    for (int j = -10; j < SIGNATURE_LENGTH + 10; j++)
                    {
                        if (i + j >= 0 && i + j < buffer_len)
                        {
                            unsigned char c = buffer[i + j];
                            /* Print visible characters as is, others as hex */
                            if (c >= 32 && c <= 126)
                            {
                                php_printf("%c", c);
                            }
                            else
                            {
                                php_printf("\\x%02x", c);
                            }
                        }
                    }
                    php_printf("'\n");

                    /* Check if there's a newline before the signature */
                    if (i > 0)
                    {
                        php_printf("DEBUG: Character before signature: \\x%02x\n", buffer[i - 1]);
                        if (buffer[i - 1] == '\n')
                        {
                            php_printf("DEBUG: Found newline before signature\n");
                        }
                    }
                }
                break;
            }
        }
    }

    if (is_encoded)
    {
        /* Get the filename we should use for key derivation - just the base name like the encoder does */
        char *filename_dup = estrndup(filename, strlen(filename));
        char *base_name = basename(filename_dup);

        if (DEBUG)
            php_printf("DEBUG: Using base filename '%s' for decryption\n", base_name);

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

        if (DEBUG)
            php_printf("DEBUG: Successfully decrypted %zu bytes of content\n", decoded_len);

        /* Debug output for decrypted content */
        if (DEBUG)
        {
            php_printf("DEBUG: Compiling decoded content in memory\n");
            php_printf("DEBUG: First 100 chars of decoded content: '");
            size_t preview_len = decoded_len > 100 ? 100 : decoded_len;
            for (size_t i = 0; i < preview_len; i++)
            {
                unsigned char c = decoded[i];
                if (c >= 32 && c <= 126 && c != '\\')
                {
                    php_printf("%c", c);
                }
                else
                {
                    php_printf("\\x%02x", c);
                }
            }
            php_printf("'\n");

            /* Write decoded content to a debug file for inspection ONLY in debug mode */
            char debug_file[MAXPATHLEN];
            snprintf(debug_file, sizeof(debug_file), "/tmp/zypher_debug_%s_%d.php",
                     basename((char *)filename), (int)time(NULL));
            FILE *df = fopen(debug_file, "wb");
            if (df)
            {
                fwrite(decoded, decoded_len, 1, df);
                fclose(df);
                php_printf("DEBUG: Wrote decoded content to debug file: %s\n", debug_file);
            }
        }

        /* SECURE IN-MEMORY COMPILATION - Use temp file approach but sanitize after use */
        char temp_file[MAXPATHLEN];
        char *temp_dir = getenv("TMPDIR");
        if (temp_dir == NULL)
        {
            temp_dir = "/tmp";
        }

        /* Create a unique filename based on timestamp and a random number */
        snprintf(temp_file, sizeof(temp_file), "%s/zypher_temp_%d_%d.php",
                 temp_dir, (int)time(NULL), rand());

        if (DEBUG)
            php_printf("DEBUG: Using temporary file for secure compilation: %s\n", temp_file);

        /* Write decoded content to temp file */
        FILE *tf = fopen(temp_file, "wb");
        if (!tf)
        {
            if (DEBUG)
                php_printf("DEBUG: Failed to create temporary file for compilation\n");
            /* Securely wipe sensitive data */
            memset(decoded, 0, decoded_len);
            efree(decoded);
            return NULL;
        }

        fwrite(decoded, decoded_len, 1, tf);
        fclose(tf);

        /* Create a clean file handle for the temporary file */
        zend_file_handle temp_file_handle;
        memset(&temp_file_handle, 0, sizeof(zend_file_handle));
        temp_file_handle.type = ZEND_HANDLE_FILENAME;
        temp_file_handle.filename = zend_string_init(temp_file, strlen(temp_file), 0);

        /* Compile using the original compiler */
        op_array = original_compile_file(&temp_file_handle, type);

        /* Immediate secure cleanup */
        unlink(temp_file); /* Delete the temp file right away */

        /* Clean up resources */
        zend_string_release(temp_file_handle.filename);

        /* Securely wipe sensitive data */
        memset(decoded, 0, decoded_len);
        efree(decoded);

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