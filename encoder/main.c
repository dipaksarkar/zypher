/**
 * Zypher PHP Encoder - Main entry point
 * Handles command line arguments and coordinates the encoding process
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>

/* Common headers */
#include "../include/zypher_encoder.h"
#include "../include/zypher_common.h"

/* Debug and error reporting functions */
void print_debug(const char *format, ...);
void print_error(const char *format, ...);

/* Forward declarations */
int encode_php_file(const zypher_encoder_options *options);
int zypher_encoder_init();
void zypher_encoder_shutdown();

/* Global debug flag */
int g_debug_mode = 0;

/* Print usage information */
void print_usage(const char *progname)
{
    printf("Zypher PHP Encoder v%s\n", ZYPHER_VERSION);
    printf("Usage: %s [options] input.php [output.php]\n\n", progname);
    printf("Options:\n");
    printf("  -h, --help               Display this help message\n");
    printf("  -v, --version            Display version information\n");
    printf("  -d, --debug              Enable debug output\n");
    printf("  -o, --output <file>      Specify output filename (default: input.encoded.php)\n");
    printf("  -e, --expire <timestamp> Set expiry timestamp (Unix timestamp)\n");
    printf("  --expire-days <days>     Set expiry in days from now\n");
    printf("  -D, --domain <domain>    Restrict execution to specified domain\n");
    printf("  -i, --iterations <num>   Set key derivation iterations (default: 5000)\n");
    printf("  --obfuscate              Enable byte rotation obfuscation\n");
    printf("  --no-phpinfo             Block phpinfo() in encoded files\n");
    printf("  --anti-debug             Enable anti-debugging features\n");
    printf("\nExample:\n");
    printf("  %s -o output.php --domain example.com --expire-days 30 input.php\n\n", progname);
    printf("  This will encode input.php to output.php, restricted to example.com domain\n");
    printf("  and will expire in 30 days.\n");
}

/* Print version information */
void print_version()
{
    printf("Zypher PHP Encoder v%s\n", ZYPHER_VERSION);
    printf("Copyright (c) 2025 Zypher Team\n");
    printf("Build: %s %s\n", __DATE__, __TIME__);
}

/* Print debug message */
void print_debug(const char *format, ...)
{
    if (!g_debug_mode)
        return;

    va_list args;
    va_start(args, format);
    fprintf(stderr, "[DEBUG] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/* Print error message */
void print_error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/* Check if file exists */
int file_exists(const char *filename)
{
    struct stat st;
    return stat(filename, &st) == 0;
}

/* Main entry point */
int main(int argc, char *argv[])
{
    int c;
    int option_index = 0;
    zypher_encoder_options options;
    char *input_file = NULL;
    char *output_file = NULL;
    int expire_days = 0;
    int result = EXIT_FAILURE;

    /* Initialize options with defaults */
    memset(&options, 0, sizeof(options));
    options.iteration_count = DEFAULT_ITERATION_COUNT;

    /* Define long options */
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"debug", no_argument, 0, 'd'},
        {"output", required_argument, 0, 'o'},
        {"expire", required_argument, 0, 'e'},
        {"expire-days", required_argument, 0, 1},
        {"domain", required_argument, 0, 'D'},
        {"iterations", required_argument, 0, 'i'},
        {"obfuscate", no_argument, 0, 2},
        {"no-phpinfo", no_argument, 0, 3},
        {"anti-debug", no_argument, 0, 4},
        {0, 0, 0, 0}};

    /* Parse command line options */
    while ((c = getopt_long(argc, argv, "hvo:e:D:di:", long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 'h':
            print_usage(basename(argv[0]));
            return EXIT_SUCCESS;
        case 'v':
            print_version();
            return EXIT_SUCCESS;
        case 'd':
            g_debug_mode = 1;
            options.debug = 1;
            break;
        case 'o':
            output_file = optarg;
            break;
        case 'e':
            options.expire_timestamp = atoi(optarg);
            break;
        case 'D':
            options.domain_lock = optarg;
            break;
        case 'i':
            options.iteration_count = atoi(optarg);
            if (options.iteration_count < 1000)
            {
                print_error("Iteration count must be at least 1000");
                return EXIT_FAILURE;
            }
            break;
        case 1: /* --expire-days */
            expire_days = atoi(optarg);
            if (expire_days > 0)
            {
                options.expire_timestamp = time(NULL) + (expire_days * 86400); /* Convert days to seconds */
            }
            break;
        case 2: /* --obfuscate */
            options.obfuscate = 1;
            break;
        case 3: /* --no-phpinfo */
            options.disable_phpinfo = 1;
            break;
        case 4: /* --anti-debug */
            options.anti_debug = 1;
            break;
        default:
            print_usage(basename(argv[0]));
            return EXIT_FAILURE;
        }
    }

    /* Get input file */
    if (optind < argc)
    {
        input_file = argv[optind++];
        /* If output file not specified but we have another argument, treat it as output file */
        if (!output_file && optind < argc)
        {
            output_file = argv[optind++];
        }
    }
    else
    {
        print_error("No input file specified");
        print_usage(basename(argv[0]));
        return EXIT_FAILURE;
    }

    /* Check if input file exists */
    if (!file_exists(input_file))
    {
        print_error("Input file does not exist: %s", input_file);
        return EXIT_FAILURE;
    }

    /* Generate default output filename if not specified */
    char default_output[4096] = {0};
    if (!output_file)
    {
        char *input_copy = strdup(input_file); // Create a copy that we own
        if (input_copy)
        {
            char *input_basename = basename(input_copy);
            char *dot = strrchr(input_basename, '.');
            if (dot)
            {
                *dot = '\0';
            }
            snprintf(default_output, sizeof(default_output), "%s.encoded.php", input_basename);
            output_file = default_output;
            free(input_copy); // Free our copy, not the result of basename
        }
        else
        {
            print_error("Memory allocation failed");
            return EXIT_FAILURE;
        }
    }

    /* Set options */
    options.input_file = input_file;
    options.output_file = output_file;

    /* Initialize encoder */
    if (zypher_encoder_init() != ZYPHER_SUCCESS)
    {
        print_error("Failed to initialize encoder");
        return EXIT_FAILURE;
    }

    /* Encode the file */
    printf("Encoding %s to %s\n", input_file, output_file);
    if (options.domain_lock)
    {
        printf("Domain lock: %s\n", options.domain_lock);
    }
    if (options.expire_timestamp)
    {
        char expire_date[64];
        struct tm *tm_info = localtime(&(time_t){options.expire_timestamp});
        strftime(expire_date, sizeof(expire_date), "%Y-%m-%d %H:%M:%S", tm_info);
        printf("Expiry date: %s\n", expire_date);
    }

    /* Do the encoding */
    if (encode_php_file(&options) == ZYPHER_SUCCESS)
    {
        printf("Encoding successful. Output written to %s\n", output_file);
        result = EXIT_SUCCESS;
    }
    else
    {
        print_error("Encoding failed");
    }

    /* Cleanup */
    zypher_encoder_shutdown();

    return result;
}