/**
 * Zypher PHP Encoder - Entry point
 * Compiles PHP code to opcodes, encrypts them, and saves to a .php file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sapi/embed/php_embed.h>

#include "../include/zypher_encoder.h"
#include "../build/zypher_master_key.h"

/* Global debug flag */
int g_debug = 0;

/* Print a debug message if debug is enabled */
void print_debug(const char *format, ...)
{
    if (!g_debug)
        return;

    va_list args;
    va_start(args, format);
    fprintf(stderr, "[DEBUG] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/* Print an error message */
void print_error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/* Show help information */
void show_help()
{
    printf("%s\n\n", ZYPHER_BANNER);
    printf("Usage: zypher [options] input.php [output.php]\n");
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help                 Display this help message\n");
    printf("  -o, --output FILE          Output file (default is input.encoded.php)\n");
    printf("  -d, --debug                Enable debug output\n");
    printf("  -b, --obfuscate            Enable additional opcode obfuscation\n");
    printf("  -e, --expire TIMESTAMP     Set expiration timestamp (0=never)\n");
    printf("  -l, --license DOMAIN       Lock encoded file to domain name\n");
    printf("  -i, --iterations COUNT     Key derivation iterations (default: 1000)\n");
    printf("  -a, --allow-debugging      Allow debugging of encoded files\n");
    printf("\n");
    printf("Examples:\n");
    printf("  zypher myfile.php\n");
    printf("  zypher -o secured.php -l example.com -e 1735689600 myfile.php\n");
}

/* Parse command line options */
int parse_options(int argc, char **argv, zypher_encoder_options *options)
{
    int c;
    int option_index = 0;

    /* Set defaults */
    memset(options, 0, sizeof(zypher_encoder_options));
    options->iteration_count = 1000; /* Default iterations for key derivation */

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"output", required_argument, 0, 'o'},
        {"debug", no_argument, 0, 'd'},
        {"obfuscate", no_argument, 0, 'b'},
        {"expire", required_argument, 0, 'e'},
        {"license", required_argument, 0, 'l'},
        {"iterations", required_argument, 0, 'i'},
        {"allow-debugging", no_argument, 0, 'a'},
        {0, 0, 0, 0}};

    while ((c = getopt_long(argc, argv, "ho:dbe:l:i:a", long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 'h':
            show_help();
            return 0;

        case 'o':
            options->output_file = strdup(optarg);
            break;

        case 'd':
            options->debug = 1;
            g_debug = 1;
            break;

        case 'b':
            options->obfuscate = 1;
            break;

        case 'e':
            options->expire_timestamp = atoi(optarg);
            break;

        case 'l':
            options->domain_lock = strdup(optarg);
            break;

        case 'i':
            options->iteration_count = atoi(optarg);
            if (options->iteration_count < 100 || options->iteration_count > 10000)
            {
                print_error("Iteration count must be between 100 and 10000");
                return 0;
            }
            break;

        case 'a':
            options->allow_debugging = 1;
            break;

        case '?':
            return 0;
        }
    }

    /* Must have at least one non-option argument (input file) */
    if (optind >= argc)
    {
        print_error("No input file specified");
        return 0;
    }

    /* Get the input file - required */
    options->input_file = strdup(argv[optind]);

    /* Set default output file if not specified */
    if (!options->output_file)
    {
        /* Use input filename + .encoded.php if no output specified */
        char *output = (char *)malloc(strlen(options->input_file) + 20);
        strcpy(output, options->input_file);

        /* Remove .php extension if present */
        char *ext = strrchr(output, '.');
        if (ext && strcmp(ext, ".php") == 0)
        {
            *ext = '\0';
        }

        /* Add encoded extension */
        strcat(output, ".encoded.php");
        options->output_file = output;
    }

    /* Debug output */
    if (options->debug)
    {
        print_debug("Input file: %s", options->input_file);
        print_debug("Output file: %s", options->output_file);
        print_debug("Obfuscation: %s", options->obfuscate ? "enabled" : "disabled");
        print_debug("Expire timestamp: %d", options->expire_timestamp);
        print_debug("Domain lock: %s", options->domain_lock ? options->domain_lock : "none");
        print_debug("Iteration count: %d", options->iteration_count);
        print_debug("Allow debugging: %s", options->allow_debugging ? "yes" : "no");
    }

    return 1;
}

/* Free resources allocated for options */
void free_options(zypher_encoder_options *options)
{
    if (options->input_file)
        free(options->input_file);
    if (options->output_file)
        free(options->output_file);
    if (options->domain_lock)
        free(options->domain_lock);
}

/* Entry point */
int main(int argc, char **argv)
{
    int result;
    zypher_encoder_options options;

    /* Display banner */
    printf("%s\n", ZYPHER_BANNER);

    /* Parse command-line options */
    if (!parse_options(argc, argv, &options))
    {
        show_help();
        return 1;
    }

/* Check if master key is available */
#ifndef ZYPHER_MASTER_KEY
    print_error("Master encryption key not found. Please run 'make master_key' first.");
    return 1;
#endif

    /* Initialize PHP embedded interpreter */
    php_embed_init(0, NULL);

    /* Initialize encoder */
    if (!zypher_encoder_init())
    {
        print_error("Failed to initialize encoder");
        php_embed_shutdown();
        return 1;
    }

    /* Encode the PHP file */
    result = encode_php_file(&options);

    /* Cleanup */
    zypher_encoder_shutdown();
    php_embed_shutdown();
    free_options(&options);

    if (result)
    {
        printf("\nEncoding successful!\n");
        printf("Output file: %s\n", options.output_file);
    }
    else
    {
        printf("\nEncoding failed.\n");
    }

    return result ? 0 : 1;
}