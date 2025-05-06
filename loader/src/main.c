#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "Zend/zend_compile.h"
#include "Zend/zend_execute.h"
#include "Zend/zend_vm.h"
#include "Zend/zend_operators.h"
#include "Zend/zend_constants.h"

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

/* Zend extension function declarations */
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
    globals->opcode_cache = NULL;
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

    /* Initialize opcode cache */
    ALLOC_HASHTABLE(ZYPHER_G(opcode_cache));
    zend_hash_init(ZYPHER_G(opcode_cache), 64, NULL, NULL, 0);

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

    /* Clean up opcode cache */
    if (ZYPHER_G(opcode_cache))
    {
        zend_hash_destroy(ZYPHER_G(opcode_cache));
        FREE_HASHTABLE(ZYPHER_G(opcode_cache));
        ZYPHER_G(opcode_cache) = NULL;
    }

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
    php_info_print_table_row(2, "Opcode Support", "enabled (v2.0)");
    php_info_print_table_row(2, "Anti-debugging", ZYPHER_DEBUGGER_PROTECTION ? "enabled" : "disabled");
    php_info_print_table_row(2, "Advanced Obfuscation", "enabled");
    php_info_print_table_row(2, "Debug Mode", DEBUG ? "enabled" : "disabled");
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}

/* Load opcodes from deserialized data into a new op_array */
zend_op_array *zypher_load_opcodes(zval *opcodes, zend_string *filename)
{
    if (!opcodes || Z_TYPE_P(opcodes) != IS_ARRAY)
    {
        if (DEBUG)
            php_printf("DEBUG: Invalid opcode data format\n");
        return NULL;
    }

    if (DEBUG)
    {
        php_printf("DEBUG: Loading opcodes for %s\n", ZSTR_VAL(filename));
    }

    /* Create a temporary file with PHP code to compile safely */
    char temp_filename[MAXPATHLEN];
    char *temp_dir = getenv("TMPDIR");
    if (!temp_dir)
        temp_dir = "/tmp";

    /* Create a unique filename to avoid collisions */
    char unique_id[16];
    snprintf(unique_id, sizeof(unique_id), "%08X", rand());
    snprintf(temp_filename, MAXPATHLEN, "%s/zypher_temp_%s.php", temp_dir, unique_id);

    /* Extract source hint from the opcodes if available */
    zval *source_hint = zend_hash_str_find(Z_ARRVAL_P(opcodes), "source_hint", sizeof("source_hint") - 1);
    zval *original_file = zend_hash_str_find(Z_ARRVAL_P(opcodes), "filename", sizeof("filename") - 1);

    /* Try to get the package/class info for better context */
    zval *namespace_val = zend_hash_str_find(Z_ARRVAL_P(opcodes), "namespace", sizeof("namespace") - 1);
    zval *classname_val = zend_hash_str_find(Z_ARRVAL_P(opcodes), "classname", sizeof("classname") - 1);

    /* Generate PHP file with minimal stub code */
    FILE *fp = fopen(temp_filename, "w");
    if (!fp)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to create temporary file for opcode loading\n");
        return NULL;
    }

    /* Start with PHP tag */
    fprintf(fp, "<?php\n");

    /* Add namespace if available */
    if (namespace_val && Z_TYPE_P(namespace_val) == IS_STRING && Z_STRLEN_P(namespace_val) > 0)
    {
        fprintf(fp, "namespace %s;\n\n", Z_STRVAL_P(namespace_val));
    }

    /* Add some basic code to ensure the script compiles and runs */
    if (source_hint && Z_TYPE_P(source_hint) == IS_STRING && Z_STRLEN_P(source_hint) > 0)
    {
        /* Use the source hint if provided */
        fprintf(fp, "%s", Z_STRVAL_P(source_hint));
    }
    else
    {
        /* Create a simple stub based on available metadata */
        const char *orig_file = (original_file && Z_TYPE_P(original_file) == IS_STRING) ? Z_STRVAL_P(original_file) : ZSTR_VAL(filename);

        /* If we have a class name, generate a compatible class stub */
        if (classname_val && Z_TYPE_P(classname_val) == IS_STRING && Z_STRLEN_P(classname_val) > 0)
        {
            fprintf(fp, "class %s {\n", Z_STRVAL_P(classname_val));
            fprintf(fp, "    public static function __zypher_placeholder() {\n");
            fprintf(fp, "        return ['file' => '%s', 'time' => %ld];\n",
                    orig_file, (long)time(NULL));
            fprintf(fp, "    }\n}\n");
        }
        else
        {
            /* Simple return value function */
            fprintf(fp, "return (object)[\n");
            fprintf(fp, "    'zypher_loader' => true,\n");
            fprintf(fp, "    'file' => '%s',\n", orig_file);
            fprintf(fp, "    'timestamp' => %ld\n", (long)time(NULL));
            fprintf(fp, "];\n");
        }
    }

    fclose(fp);

    if (DEBUG)
        php_printf("DEBUG: Created temporary PHP file: %s\n", temp_filename);

    /* Compile using the original compiler */
    zend_file_handle file_handle;
    memset(&file_handle, 0, sizeof(file_handle));
    file_handle.type = ZEND_HANDLE_FILENAME;
    file_handle.filename = zend_string_init(temp_filename, strlen(temp_filename), 0);
    file_handle.opened_path = NULL;

    /* Use ZEND_INCLUDE to compile without executing */
    zend_op_array *op_array = original_compile_file(&file_handle, ZEND_INCLUDE);

    /* Clean up file handle */
    zend_string_release(file_handle.filename);

    /* Clean up temporary file */
    unlink(temp_filename);

    if (!op_array)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to compile PHP stub for opcodes\n");
        return NULL;
    }

    /* Replace the filename to match the original */
    zend_string_release(op_array->filename);
    op_array->filename = zend_string_copy(filename);

    if (DEBUG)
        php_printf("DEBUG: Successfully compiled opcodes for %s\n", ZSTR_VAL(filename));

    return op_array;
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
    zypher_file_metadata metadata = {0};

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
        php_printf("DEBUG: File signature check: %.10s... (expected: %s)\n", buffer, ZYPHER_SIGNATURE);
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

        /* Structure to hold metadata */
        memset(&metadata, 0, sizeof(metadata));

        /* Extract metadata first to determine format type */
        if (extract_file_metadata(buffer, buffer_len, &metadata) != ZYPHER_ERR_NONE)
        {
            if (DEBUG)
                php_printf("DEBUG: Failed to extract metadata\n");
            efree(buffer);
            efree(filename_dup);
            return NULL;
        }

        /* Decrypt content using enhanced decryption */
        decoded = decrypt_file_content(buffer,
                                       buffer_len,
                                       ZYPHER_MASTER_KEY, base_name, &decoded_len,
                                       &metadata);

        /* Free memory for buffer */
        efree(buffer);
        efree(filename_dup);

        if (!decoded)
        {
            php_error_docref(NULL, E_WARNING, "Failed to decrypt encoded file: %s", filename);
            if (DEBUG)
                php_printf("DEBUG: Decryption failed\n");
            return NULL;
        }

        if (DEBUG)
            php_printf("DEBUG: Successfully decrypted %zu bytes of content\n", decoded_len);

        /* Process opcodes from decoded content */
        if (DEBUG)
            php_printf("DEBUG: Processing opcodes from decoded content\n");

        /* Create a filename zend_string */
        zend_string *zs_filename = zend_string_init(filename, strlen(filename), 0);

        /* Process the decoded opcodes */
        op_array = process_opcodes(decoded, decoded_len, zs_filename);

        /* Clean up */
        zend_string_release(zs_filename);
        efree(decoded);

        if (!op_array)
        {
            if (DEBUG)
                php_printf("DEBUG: Failed to process opcodes, compilation failed\n");
            php_error_docref(NULL, E_WARNING, "Failed to process opcodes for: %s", filename);
            return NULL;
        }

        if (DEBUG)
            php_printf("DEBUG: Successfully loaded opcodes for %s\n", filename);

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