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
#include "Zend/zend_compile.h"
#include "php_zypher.h"
#include <libgen.h>

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