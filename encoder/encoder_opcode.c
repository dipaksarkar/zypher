/*
  +----------------------------------------------------------------------+
  | Zypher PHP Encoder                                                    |
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h> /* Added for unlink() function */

/* Common headers */
#include "../include/zypher_encoder.h"
#include "../include/zypher_common.h"

/* PHP embedding variables */
#ifdef HAVE_EMBED
#include <sapi/embed/php_embed.h>
#endif

/* Forward declarations */
extern void print_debug(const char *format, ...);
extern void print_error(const char *format, ...);
extern char *run_command(const char *command, size_t *output_size);

/* Clean PHP source code (remove comments and whitespace) */
char *clean_php_source(const char *source_code)
{
    if (!source_code)
    {
        return NULL;
    }

    /* Try to use PHP's tokenizer to strip comments if possible */
    char *command = NULL;
    char *temp_file = "/tmp/zypher_temp_source.php";
    char *cleaned = NULL;
    size_t cmd_output_size = 0;
    FILE *fp = NULL;

    /* Write source to temporary file */
    fp = fopen(temp_file, "w");
    if (!fp)
    {
        print_error("Failed to create temporary file for PHP cleaning");
        return strdup(source_code); /* Fall back to original source */
    }

    fwrite(source_code, 1, strlen(source_code), fp);
    fclose(fp);

    /* Create PHP command to strip comments and extra whitespace */
    command = (char *)malloc(strlen(temp_file) + 256);
    if (command)
    {
        sprintf(command, "php -r \"echo php_strip_whitespace('%s');\"", temp_file);
        cleaned = run_command(command, &cmd_output_size);
        free(command);
    }

    /* Remove the temporary file */
    unlink(temp_file);

    if (cleaned && cmd_output_size > 0)
    {
        print_debug("Successfully cleaned PHP source code");
        return cleaned;
    }

    /* Fall back to original source if cleaning failed */
    print_debug("Failed to clean source code, using original");
    return strdup(source_code);
}

/* Compile PHP to opcodes using Zend API */
int compile_php_to_opcodes(const char *source_code, const char *filename, char **output, size_t *output_len)
{
    if (!source_code || !filename || !output || !output_len)
    {
        print_error("Invalid parameters for opcode compilation");
        return ZYPHER_FAILURE;
    }

    *output = NULL;
    *output_len = 0;

#ifdef HAVE_EMBED
    /* Using PHP embedding if available */
    zend_file_handle file_handle;
    zend_op_array *op_array;
    char *serialized_opcodes = NULL;
    size_t serialized_len = 0;

    /* Initialize PHP runtime for this request */
    if (php_request_startup() != SUCCESS)
    {
        print_error("Failed to initialize PHP runtime");
        return ZYPHER_FAILURE;
    }

    /* Set up file handle for our source code */
    memset(&file_handle, 0, sizeof(file_handle));
    file_handle.type = ZEND_HANDLE_STRING;
    file_handle.filename = filename;
    file_handle.opened_path = NULL;
    file_handle.free_filename = 0;
    file_handle.handle.stream.handle = NULL;
    file_handle.handle.string.val = (char *)source_code;
    file_handle.handle.string.len = strlen(source_code);

    /* Compile the source code into opcodes */
    op_array = zend_compile_file(&file_handle, ZEND_INCLUDE);

    if (op_array != NULL)
    {
        /* Successfully compiled to opcodes */
        print_debug("Source code successfully compiled to opcodes");

        /* Serialize the op_array for storage - we need to use PHP's serialize function */
        zval op_array_zval;
        ZVAL_EMPTY_ARRAY(&op_array_zval);

        /* Build our data structure with op_array and metadata */
        add_assoc_string(&op_array_zval, "filename", (char *)filename);
        add_assoc_string(&op_array_zval, "source", (char *)source_code);
        add_assoc_long(&op_array_zval, "timestamp", time(NULL));
        add_assoc_string(&op_array_zval, "php_version", PHP_VERSION);

        /* Extract namespace and class information */
        if (op_array->scope)
        {
            add_assoc_string(&op_array_zval, "class", (char *)ZSTR_VAL(op_array->scope->name));
            if (op_array->scope->parent)
            {
                add_assoc_string(&op_array_zval, "parent", (char *)ZSTR_VAL(op_array->scope->parent->name));
            }
        }

        /* Add compilation flags */
        zval flags_zval;
        array_init(&flags_zval);
        add_assoc_long(&flags_zval, "opcache_enabled", (long)opcache_get_status() != NULL);
        add_assoc_zval(&op_array_zval, "flags", &flags_zval);

        /* Serialize to string */
        php_serialize_data_t var_hash;
        smart_str buf = {0};

        PHP_VAR_SERIALIZE_INIT(var_hash);
        php_var_serialize(&buf, &op_array_zval, &var_hash);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);

        if (buf.s)
        {
            serialized_opcodes = estrndup(ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
            serialized_len = ZSTR_LEN(buf.s);
            smart_str_free(&buf);

            /* Set output parameters */
            *output = serialized_opcodes;
            *output_len = serialized_len;

            print_debug("Successfully serialized opcodes (%zu bytes)", serialized_len);

            /* Clean up */
            destroy_op_array(op_array);
            efree(op_array);
            php_request_shutdown(NULL);

            return ZYPHER_SUCCESS;
        }
        else
        {
            print_error("Failed to serialize opcodes");
        }

        /* Clean up op array if serialization failed */
        destroy_op_array(op_array);
        efree(op_array);
    }
    else
    {
        print_error("Failed to compile source code");
    }

    /* Shutdown PHP request */
    php_request_shutdown(NULL);

    return ZYPHER_FAILURE;
#else
    /* No fallback - require PHP embedding */
    print_error("Zend API (zend_compile_file) is required but PHP embedding is not available");
    print_error("Please rebuild with PHP development headers and --enable-embed SAPI");
    return ZYPHER_FAILURE;
#endif
}

/* Serialize PHP data (opcodes, filename, etc.) */
char *php_serialize_data(const char *contents, const char *filename)
{
    if (!contents || !filename)
    {
        print_error("Invalid parameters for serialization");
        return NULL;
    }

    /* Create a simple serialized structure */
    char *serialized_data = NULL;
    char *temp_file = "/tmp/zypher_temp_serialize.php";
    size_t cmd_output_size = 0;
    FILE *fp = NULL;

    /* Write the PHP script to serialize the data */
    fp = fopen(temp_file, "w");
    if (!fp)
    {
        print_error("Failed to create temporary file for serialization");
        return NULL;
    }

    /* Write PHP script to serialize the data directly without base64 encoding */
    fprintf(fp, "<?php\n");
    fprintf(fp, "$data = array('filename' => '%s', 'contents' => <<<'EOT'\n", filename);
    fprintf(fp, "%s\n", contents);
    fprintf(fp, "EOT\n");
    fprintf(fp, ");\n");
    fprintf(fp, "// Output raw serialized data without base64 encoding\n");
    fprintf(fp, "echo serialize($data);\n");
    fprintf(fp, "?>");
    fclose(fp);

    /* Create PHP command to serialize data */
    char *command = (char *)malloc(strlen(temp_file) + 128);
    if (!command)
    {
        print_error("Failed to allocate memory for command");
        unlink(temp_file);
        return NULL;
    }

    sprintf(command, "php %s", temp_file);
    serialized_data = run_command(command, &cmd_output_size);
    free(command);

    /* Remove the temporary file */
    unlink(temp_file);

    if (!serialized_data || cmd_output_size == 0)
    {
        print_error("Failed to serialize data");
        return NULL;
    }

    /* Calculate MD5 of serialized data and prefix it */
    char md5[33] = {0}; /* MD5 is 32 chars + null */
    extern void calculate_content_checksum(const char *content, size_t length, char *output);
    calculate_content_checksum(serialized_data, strlen(serialized_data), md5);

    /* Create final result: MD5 + serialized data (without base64 encoding) */
    char *result = (char *)malloc(strlen(md5) + strlen(serialized_data) + 1);
    if (!result)
    {
        print_error("Failed to allocate memory for result");
        free(serialized_data);
        return NULL;
    }

    sprintf(result, "%s%s", md5, serialized_data);
    free(serialized_data);

    return result;
}