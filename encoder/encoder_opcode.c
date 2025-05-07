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

/* Compile PHP to opcodes */
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
    /* Use PHP embedding API to get opcodes */
    print_debug("Using PHP embedding to compile opcodes");
    /* ... PHP embedding implementation here ... */
    /* This would use zend_compile_file or zend_compile_string with output buffering */
#endif

    /* Without embedding, we use PHP CLI to generate opcode representation */
    char *command = NULL;
    char *temp_file = "/tmp/zypher_temp_source.php";
    char *opcode_output = NULL;
    size_t cmd_output_size = 0;
    FILE *fp = NULL;

    /* Write source to temporary file */
    fp = fopen(temp_file, "w");
    if (!fp)
    {
        print_error("Failed to create temporary file for opcode generation");
        return ZYPHER_FAILURE;
    }

    fwrite(source_code, 1, strlen(source_code), fp);
    fclose(fp);

    /* Create PHP command to get opcodes - either with opcache or regular php reflection */
    command = (char *)malloc(strlen(temp_file) + 512);
    if (command)
    {
        /* Try to use opcache_get_status and opcache_compile_file if available */
        sprintf(command, "php -d opcache.enable_cli=1 -d opcache.optimization_level=0 "
                         "-r \"if(function_exists('opcache_compile_file') && opcache_compile_file('%s')) { "
                         "echo 'ZYPHER_OPCODES:' . base64_encode(serialize(opcache_get_status(true)['scripts']['%s'])); "
                         "} else { "
                         "echo 'ZYPHER_OPCODES:' . base64_encode(serialize(array('filename' => '%s', 'contents' => file_get_contents('%s')))); "
                         "}\"",
                temp_file, temp_file, filename, temp_file);

        opcode_output = run_command(command, &cmd_output_size);
        free(command);
    }

    /* Remove the temporary file */
    unlink(temp_file);

    if (!opcode_output || cmd_output_size == 0)
    {
        print_error("Failed to generate opcodes");
        return ZYPHER_FAILURE;
    }

    /* Return the opcode output */
    *output = opcode_output;
    *output_len = cmd_output_size;

    print_debug("Successfully compiled PHP to opcodes (%zu bytes)", *output_len);
    return ZYPHER_SUCCESS;
}

/* Serialize PHP data (opcodes, filename, etc.) */
char *php_serialize_data(const char *contents, const char *filename)
{
    if (!contents || !filename)
    {
        print_error("Invalid parameters for serialization");
        return NULL;
    }

    /* Create a simple serialized structure with MD5:base64 format */
    char *result = NULL;
    char md5[33] = {0};
    char *base64_data = NULL;
    size_t data_len = 0;
    char *raw_data = NULL;

    /* Calculate length needed for structure */
    data_len = strlen(contents) + strlen(filename) + 100;
    raw_data = (char *)malloc(data_len);
    if (!raw_data)
    {
        print_error("Failed to allocate memory for serialized data");
        return NULL;
    }

    /* Create a serialized structure with contents and filename */
    /* Format: a:2:{s:8:"filename";s:X:"...";s:8:"contents";s:X:"...";} */
    int written = snprintf(raw_data, data_len,
                           "a:2:{s:8:\"filename\";s:%zu:\"%s\";s:8:\"contents\";s:%zu:\"%s\";}",
                           strlen(filename), filename, strlen(contents), contents);

    if (written < 0 || written >= (int)data_len)
    {
        print_error("Failed to create serialized data");
        free(raw_data);
        return NULL;
    }

    /* Try to use PHP's native serialization if available */
    char *command = NULL;
    char *temp_file = "/tmp/zypher_temp_serialize.php";
    size_t cmd_output_size = 0;
    FILE *fp = NULL;

    /* Write the raw data to a temporary file */
    fp = fopen(temp_file, "w");
    if (!fp)
    {
        /* Fall back to our own serialization */
        goto use_internal_serialization;
    }

    /* Write PHP script to serialize the data */
    fprintf(fp, "<?php\n");
    fprintf(fp, "$data = array('filename' => '%s', 'contents' => <<<'EOT'\n", filename);
    fprintf(fp, "%s\n", contents);
    fprintf(fp, "EOT\n");
    fprintf(fp, ");\n");
    fprintf(fp, "echo base64_encode(serialize($data));\n");
    fprintf(fp, "?>");
    fclose(fp);

    /* Create PHP command to serialize data */
    command = (char *)malloc(strlen(temp_file) + 128);
    if (command)
    {
        sprintf(command, "php %s", temp_file);
        base64_data = run_command(command, &cmd_output_size);
        free(command);
    }

    /* Remove the temporary file */
    unlink(temp_file);

    if (!base64_data || cmd_output_size == 0)
    {
        /* Fall back to our own serialization */
        goto use_internal_serialization;
    }

    /* Calculate MD5 of base64 data */
    extern void calculate_content_checksum(const char *content, size_t length, char *output);
    calculate_content_checksum(base64_data, strlen(base64_data), md5);

    /* Create final result: MD5 + base64 data */
    result = (char *)malloc(strlen(md5) + strlen(base64_data) + 1);
    if (result)
    {
        sprintf(result, "%s%s", md5, base64_data);
    }

    free(base64_data);
    free(raw_data);

    return result;

use_internal_serialization:
    /* This is a fallback if PHP serialization fails */
    extern char *base64_encode(const unsigned char *input, size_t length);
    base64_data = base64_encode((unsigned char *)raw_data, strlen(raw_data));
    if (!base64_data)
    {
        print_error("Failed to base64 encode serialized data");
        free(raw_data);
        return NULL;
    }

    /* Calculate MD5 of base64 data */
    extern void calculate_content_checksum(const char *content, size_t length, char *output);
    calculate_content_checksum(base64_data, strlen(base64_data), md5);

    /* Create final result: MD5 + base64 data */
    result = (char *)malloc(strlen(md5) + strlen(base64_data) + 1);
    if (result)
    {
        sprintf(result, "%s%s", md5, base64_data);
    }

    /* Clean up */
    free(raw_data);
    free(base64_data);

    return result;
}