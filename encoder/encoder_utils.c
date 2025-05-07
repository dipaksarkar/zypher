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
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>

/* Common headers */
#include "../include/zypher_encoder.h"
#include "../include/zypher_common.h"

/* Forward declarations */
extern void print_debug(const char *format, ...);
extern void print_error(const char *format, ...);

/* Buffer for temporary calculations */
static char error_buffer[8192];

/* Read file contents */
char *read_file_contents(const char *filename, size_t *size)
{
    FILE *fp;
    char *buffer = NULL;
    size_t file_size;
    struct stat st;

    /* Open the file */
    fp = fopen(filename, "rb");
    if (!fp)
    {
        snprintf(error_buffer, sizeof(error_buffer), "Failed to open file: %s (%s)",
                 filename, strerror(errno));
        print_error("%s", error_buffer);
        return NULL;
    }

    /* Get file size */
    if (stat(filename, &st) == 0)
    {
        file_size = st.st_size;
    }
    else
    {
        fclose(fp);
        print_error("Failed to determine file size: %s", filename);
        return NULL;
    }

    /* Allocate buffer for file contents */
    buffer = (char *)malloc(file_size + 1);
    if (!buffer)
    {
        fclose(fp);
        print_error("Failed to allocate memory for file contents");
        return NULL;
    }

    /* Read file contents */
    if (fread(buffer, 1, file_size, fp) != file_size)
    {
        fclose(fp);
        free(buffer);
        print_error("Failed to read file contents: %s", filename);
        return NULL;
    }

    /* Null terminate the buffer */
    buffer[file_size] = '\0';

    /* Close the file */
    fclose(fp);

    /* Set the size if requested */
    if (size)
    {
        *size = file_size;
    }

    return buffer;
}

/* Execute a command and capture its output */
char *run_command(const char *command, size_t *output_size)
{
    FILE *fp;
    char buffer[4096];
    size_t total_size = 0;
    size_t buffer_size = 4096;
    size_t bytes_read;
    char *output = NULL;
    char *new_output;

    if (!command || !output_size)
    {
        print_error("Invalid parameters for command execution");
        return NULL;
    }

    *output_size = 0;

    /* Open process */
    fp = popen(command, "r");
    if (!fp)
    {
        print_error("Failed to execute command: %s", command);
        return NULL;
    }

    /* Allocate output buffer */
    output = (char *)malloc(buffer_size);
    if (!output)
    {
        pclose(fp);
        print_error("Failed to allocate memory for command output");
        return NULL;
    }

    /* Read command output */
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        /* Check if we need to resize the output buffer */
        if (total_size + bytes_read >= buffer_size)
        {
            buffer_size *= 2;
            new_output = (char *)realloc(output, buffer_size);
            if (!new_output)
            {
                free(output);
                pclose(fp);
                print_error("Failed to resize output buffer");
                return NULL;
            }
            output = new_output;
        }

        /* Copy the data to the output buffer */
        memcpy(output + total_size, buffer, bytes_read);
        total_size += bytes_read;
    }

    /* Null terminate the output */
    if (total_size < buffer_size)
    {
        output[total_size] = '\0';
    }
    else
    {
        /* Resize to make space for null terminator */
        new_output = (char *)realloc(output, total_size + 1);
        if (new_output)
        {
            output = new_output;
            output[total_size] = '\0';
        }
    }

    /* Close the process */
    pclose(fp);

    /* Set the output size */
    *output_size = total_size;

    return output;
}

/* Create the final output file with PHP stub and encoded content */
int create_stub_file(const char *filename, const char *encoded_content, size_t content_len,
                     const zypher_encoder_options *options)
{
    FILE *fp;
    static const char *stub = "<?php\n"
                              "if(!extension_loaded('zypher')){die('The file '.__FILE__."
                              "\" is corrupted.\\n\\nScript error: the \"."
                              "((php_sapi_name()=='cli') ?'Zypher':'<a href=\\\"https://www.zypher.com\\\">Zypher</a>')."
                              "\" Loader for PHP needs to be installed.\\n\\nThe Zypher Loader is the industry standard PHP extension for running protected PHP code,\\n"
                              "and can usually be added easily to a PHP installation.\\n\\nFor Loaders please visit\"."
                              "((php_sapi_name()=='cli')?\":\\n\\nhttps://get-loader.zypher.com\\n\\nFor\":' <a href=\\\"https://get-loader.zypher.com\\\">get-loader.zypher.com</a> and for')."
                              "\" an instructional video please see\"."
                              "((php_sapi_name()=='cli')?\":\\n\\nhttp://zypher.be/LV\\n\\n\":' <a href=\\\"http://zypher.be/LV\\\">http://zypher.be/LV</a> ')."
                              "\"\");}exit(0);\n"
                              "?>\n";

    /* Calculate line length from encoded content's first line */
    int content_line_length = 0;
    const char *newline = strchr(encoded_content, '\n');
    if (newline)
    {
        content_line_length = (int)(newline - encoded_content);
    }
    else
    {
        /* Default length if no newline found */
        content_line_length = 76;
    }

    /* Make sure we have at least SIGNATURE_LENGTH + 1 for "+" */
    if (content_line_length < SIGNATURE_LENGTH + 1)
    {
        content_line_length = 76; /* Default standard Base64 line length */
    }

    char padded_signature[content_line_length + 1];

    /* Create signature with random Base64-like padding */
    int pos = 0;
    memcpy(padded_signature + pos, ZYPHER_SIGNATURE, SIGNATURE_LENGTH);
    pos += SIGNATURE_LENGTH;

    /* Add '+' character right after ZYPH01 */
    if (pos < content_line_length)
    {
        padded_signature[pos++] = '+';
    }

    /* Base64 character set (without '+') */
    const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/";
    int base64_chars_len = strlen(base64_chars);

    /* Fill the rest with random Base64-like characters */
    while (pos < content_line_length)
    {
        /* Generate a random index into the Base64 character set */
        int random_index = rand() % base64_chars_len;
        padded_signature[pos++] = base64_chars[random_index];
    }
    padded_signature[content_line_length] = '\0';

    if (!filename || !encoded_content)
    {
        print_error("Invalid parameters for stub file creation");
        return ZYPHER_FAILURE;
    }

    fp = fopen(filename, "w");
    if (!fp)
    {
        print_error("Failed to open output file: %s", filename);
        return ZYPHER_FAILURE;
    }

    /* Write stub */
    if (fwrite(stub, 1, strlen(stub), fp) != strlen(stub))
    {
        print_error("Failed to write PHP stub to file");
        fclose(fp);
        return ZYPHER_FAILURE;
    }

    /* Write padded signature */
    if (fwrite(padded_signature, 1, strlen(padded_signature), fp) != strlen(padded_signature))
    {
        print_error("Failed to write signature to file");
        fclose(fp);
        return ZYPHER_FAILURE;
    }

    /* Add a newline after the padded signature */
    if (fwrite("\n", 1, 1, fp) != 1)
    {
        print_error("Failed to write newline after signature");
        fclose(fp);
        return ZYPHER_FAILURE;
    }

    /* Write encoded content */
    if (fwrite(encoded_content, 1, content_len, fp) != content_len)
    {
        print_error("Failed to write encoded content to file");
        fclose(fp);
        return ZYPHER_FAILURE;
    }

    /* Close the file */
    fclose(fp);

    print_debug("Encoded file created successfully: %s", filename);
    return ZYPHER_SUCCESS;
}

/* Get formatted timestamp string */
char *get_timestamp_string(uint32_t timestamp)
{
    static char buffer[64];
    struct tm *timeinfo;
    time_t time_value = timestamp;

    timeinfo = localtime(&time_value);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

    return buffer;
}