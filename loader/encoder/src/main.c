#include "../include/zypher_encoder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

/* Path to the master key file */
#define MASTER_KEY_FILE ".zypher_key"

/* Main entry point for the encoder */
int main(int argc, char *argv[])
{
    zypher_options_t options;
    zypher_file_t *file_info;
    char *master_key_file;
    char *master_key = NULL;
    char *executable_path;
    char *executable_dir;
    int result = 0;

    /* Initialize encoder */
    if (!zypher_encoder_init())
    {
        fprintf(stderr, "Error: Failed to initialize encoder\n");
        return 1;
    }

    /* Parse command line arguments */
    if (!zypher_parse_options(argc, argv, &options))
    {
        zypher_encoder_cleanup();
        return 1;
    }

    /* Show help or version if requested */
    if (options.show_help)
    {
        zypher_print_help(argv[0]);
        zypher_encoder_cleanup();
        return 0;
    }

    if (options.show_version)
    {
        zypher_print_version();
        zypher_encoder_cleanup();
        return 0;
    }

    /* Get executable directory for key storage */
    executable_path = strdup(argv[0]);
    executable_dir = dirname(executable_path);

    /* Determine master key file path */
    master_key_file = malloc(strlen(executable_dir) + strlen(MASTER_KEY_FILE) + 2);
    if (master_key_file)
    {
        sprintf(master_key_file, "%s/%s", executable_dir, MASTER_KEY_FILE);
    }
    else
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(executable_path);
        zypher_encoder_cleanup();
        return 1;
    }

    /* Check if master key exists, if not generate a new one */
    master_key = zypher_load_master_key(master_key_file);
    if (!master_key)
    {
        /* Generate a new master key */
        if (options.verbose)
        {
            printf("Generating new master key...\n");
        }

        master_key = zypher_generate_random_key(32);
        if (!master_key)
        {
            fprintf(stderr, "Error: Failed to generate master key\n");
            free(master_key_file);
            free(executable_path);
            zypher_encoder_cleanup();
            return 1;
        }

        /* Save the master key */
        if (!zypher_save_master_key(master_key, master_key_file))
        {
            fprintf(stderr, "Warning: Failed to save master key to %s\n", master_key_file);
            /* Continue anyway - this is not a fatal error */
        }
    }

    /* Store master key in options */
    options.master_key = master_key;

    if (options.verbose)
    {
        printf("Zypher Encoder v%s\n", ZYPHER_ENCODER_VERSION);
        printf("Source path: %s\n", options.source_path);
        printf("Output path: %s\n", options.output_path);
    }

    /* Get information about the source path */
    file_info = zypher_get_file_info(options.source_path);
    if (!file_info)
    {
        fprintf(stderr, "Error: Could not access source path: %s\n", options.source_path);
        free(master_key);
        free(master_key_file);
        free(executable_path);
        zypher_encoder_cleanup();
        return 1;
    }

    /* Process based on whether source is a directory or file */
    if (file_info->is_directory)
    {
        /* Process directory */
        if (options.verbose)
        {
            printf("Processing directory: %s\n", options.source_path);
        }

        result = zypher_process_directory(options.source_path, options.output_path, &options);
    }
    else
    {
        /* Process single file */
        if (options.verbose)
        {
            printf("Processing file: %s\n", options.source_path);
        }

        /* Check if file is a PHP file */
        if (zypher_is_php_file(options.source_path))
        {
            result = zypher_encode_file(options.source_path, options.output_path, &options);

            if (result && options.verbose)
            {
                printf("Successfully encoded: %s -> %s\n", options.source_path, options.output_path);
            }
        }
        else
        {
            /* Just copy the file */
            char *content;
            size_t size;

            content = zypher_read_file_contents(options.source_path, &size);
            if (!content)
            {
                fprintf(stderr, "Error: Failed to read file: %s\n", options.source_path);
                result = 0;
            }
            else
            {
                result = zypher_write_file_contents(options.output_path, content, size);

                if (result && options.verbose)
                {
                    printf("Copied non-PHP file: %s -> %s\n", options.source_path, options.output_path);
                }

                free(content);
            }
        }
    }

    /* Clean up */
    zypher_free_file_info(file_info);
    free(master_key);
    free(master_key_file);
    free(executable_path);

    /* Free exclude patterns */
    if (options.exclude_patterns)
    {
        for (int i = 0; i < options.exclude_count; i++)
        {
            free(options.exclude_patterns[i]);
        }
        free(options.exclude_patterns);
    }

    free(options.source_path);
    free(options.output_path);

    /* Finalize */
    zypher_encoder_cleanup();

    if (result)
    {
        if (options.verbose)
        {
            printf("Encoding completed successfully.\n");
        }
        return 0;
    }
    else
    {
        fprintf(stderr, "Encoding failed.\n");
        return 1;
    }
}