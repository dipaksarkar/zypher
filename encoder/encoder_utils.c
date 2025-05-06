/**
 * Zypher PHP Encoder - Utility functionality
 * Provides helper functions for file operations and encoding
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

/* Common headers */
#include "../include/zypher_encoder.h"
#include "../include/zypher_common.h"

/* External debug function */
extern void print_debug(const char *format, ...);
extern void print_error(const char *format, ...);

/* Helper function to read a file into memory */
char *read_file_contents(const char *filename, size_t *size)
{
    FILE *fp;
    char *contents;
    size_t file_size;
    struct stat st;

    /* Get file size */
    if (stat(filename, &st) != 0)
    {
        print_error("Error accessing file %s: %s", filename, strerror(errno));
        return NULL;
    }

    file_size = st.st_size;
    if (file_size <= 0)
    {
        print_error("File %s is empty", filename);
        return NULL;
    }

    /* Open the file */
    fp = fopen(filename, "rb");
    if (!fp)
    {
        print_error("Error opening file %s: %s", filename, strerror(errno));
        return NULL;
    }

    /* Allocate memory for file contents */
    contents = (char *)malloc(file_size + 1);
    if (!contents)
    {
        print_error("Error allocating memory for file contents");
        fclose(fp);
        return NULL;
    }

    /* Read the file */
    if (fread(contents, 1, file_size, fp) != file_size)
    {
        print_error("Error reading file %s: %s", filename, strerror(errno));
        fclose(fp);
        free(contents);
        return NULL;
    }

    /* Add null terminator */
    contents[file_size] = '\0';

    /* Close file */
    fclose(fp);

    /* Set size if requested */
    if (size)
    {
        *size = file_size;
    }

    return contents;
}

/* Helper function to run shell commands */
char *run_command(const char *command, size_t *output_size)
{
    FILE *pipe;
    char *output = NULL;
    char buffer[1024];
    size_t capacity = 0;
    size_t size = 0;

    /* Open pipe for command */
    pipe = popen(command, "r");
    if (!pipe)
    {
        print_error("Error executing command: %s", command);
        return NULL;
    }

    /* Read output */
    while (fgets(buffer, sizeof(buffer), pipe) != NULL)
    {
        size_t len = strlen(buffer);

        /* Resize the output buffer if needed */
        if (size + len >= capacity)
        {
            capacity = capacity == 0 ? 1024 : capacity * 2;
            char *new_output = realloc(output, capacity);
            if (!new_output)
            {
                print_error("Error allocating memory for command output");
                free(output);
                pclose(pipe);
                return NULL;
            }
            output = new_output;
        }

        /* Append to output */
        memcpy(output + size, buffer, len);
        size += len;
    }

    /* Close pipe and check status */
    int status = pclose(pipe);
    if (status != 0)
    {
        print_error("Command failed with status %d", status);
        free(output);
        return NULL;
    }

    /* Add null terminator */
    if (output)
    {
        if (size + 1 >= capacity)
        {
            char *new_output = realloc(output, size + 1);
            if (new_output)
            {
                output = new_output;
            }
        }
        output[size] = '\0';

        if (output_size)
        {
            *output_size = size;
        }
    }

    return output;
}

/* Base64 encode binary data */
char *base64_encode(const unsigned char *input, size_t length)
{
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /* Calculate output size with padding */
    size_t output_length = 4 * ((length + 2) / 3);
    char *output = malloc(output_length + 1);

    if (!output)
        return NULL;

    /* Process input 3 bytes at a time */
    size_t i = 0;
    size_t j = 0;

    while (i < length)
    {
        uint32_t octet_a = i < length ? input[i++] : 0;
        uint32_t octet_b = i < length ? input[i++] : 0;
        uint32_t octet_c = i < length ? input[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        output[j++] = base64_chars[(triple >> 18) & 0x3F];
        output[j++] = base64_chars[(triple >> 12) & 0x3F];
        output[j++] = base64_chars[(triple >> 6) & 0x3F];
        output[j++] = base64_chars[triple & 0x3F];
    }

    /* Add padding if needed */
    switch (length % 3)
    {
    case 1:
        output[output_length - 2] = '=';
        output[output_length - 1] = '=';
        break;
    case 2:
        output[output_length - 1] = '=';
        break;
    }

    output[output_length] = '\0';
    return output;
}

/* Create a stub PHP file with encoded data */
int create_stub_file(const char *filename, const char *encoded_content, size_t content_len,
                     const zypher_encoder_options *options)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp)
    {
        print_error("Error creating output file %s: %s", filename, strerror(errno));
        return 0;
    }

    /* Write PHP file header */
    fprintf(fp, "<?php\n");
    fprintf(fp, "/**\n");
    fprintf(fp, " * Zypher Encoded PHP File\n");

    /* Fix the time formatting issue with proper time_t variable */
    time_t current_time = time(NULL);
    fprintf(fp, " * Generated: %s", ctime(&current_time));

    fprintf(fp, " * Copyright (c) %d Zypher Encoder\n", 2025);
    fprintf(fp, " * \n");
    fprintf(fp, " * This file is encoded and can only be executed with the Zypher loader extension.\n");
    fprintf(fp, " * For more information, visit https://www.zypher.com/\n");
    fprintf(fp, " */\n\n");

    /* License check code */
    if (options->expire_timestamp > 0 || options->domain_lock)
    {
        fprintf(fp, "// License Information\n");
        if (options->expire_timestamp > 0)
        {
            /* Fix expire timestamp handling */
            time_t expire_time = (time_t)options->expire_timestamp;
            fprintf(fp, "// Expires: %s", ctime(&expire_time));
        }
        if (options->domain_lock)
        {
            fprintf(fp, "// Domain: %s\n", options->domain_lock);
        }
        fprintf(fp, "\n");
    }

    /* Loader check */
    fprintf(fp, "if (!extension_loaded('zypher')) {\n");
    fprintf(fp, "    die('This file was encoded with Zypher Encoder and requires the Zypher loader extension.');\n");
    fprintf(fp, "}\n\n");
    fprintf(fp, "?>");
    /* Write the encoded data */
    fprintf(fp, "// ZYPHER:%s", encoded_content);

    fclose(fp);
    return 1;
}