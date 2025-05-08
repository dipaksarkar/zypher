#include <stdio.h>
#include <php_embed.h>
#include <zend_compile.h>
#include <zend_execute.h>
#include <string.h>
#include <libgen.h>
#include <stdlib.h>

// Function prototype declarations
void serialize_opcodes(const zend_op_array *op_array, const char *output_file);
void export_opcodes_text(const zend_op_array *op_array, const char *output_file);
int validate_opcode_binary(const char *binary_file);
void hex_dump(const char *binary_file, const char *output_file);

// Function to get the full filename (without changing it) from a path
char *get_full_filename(const char *path)
{
    // Make a copy of the path since basename/dirname may modify it
    char *path_copy = strdup(path);
    if (!path_copy)
    {
        return NULL;
    }

    // Get just the filename part (no directory)
    char *filename = basename(path_copy);

    // Create a new string for the result (since we'll free path_copy)
    char *result = strdup(filename);
    free(path_copy);

    return result;
}

void print_usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s <input.php> [output.php] [options]\n\n", program_name);
    fprintf(stderr, "If output file is omitted, it will be named input.php.zypher\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --dump                    Generate dump files with extensions appended:\n");
    fprintf(stderr, "                            input.php.dis (disassembly) and input.php.hex (hexdump)\n");
    fprintf(stderr, "  --validate                Validate the binary opcode file format\n");
    fprintf(stderr, "  --help                    Display this help message\n");
}

int main(int argc, char **argv)
{
    if (argc < 2 || (argc >= 2 && strcmp(argv[1], "--help") == 0))
    {
        print_usage(argv[0]);
        return 1;
    }

    char *input_file = argv[1];
    char *output_file = NULL;

    int dump_flag = 0;
    int validate_flag = 0;
    int arg_start_idx = 2;

    // Handle the optional output file parameter
    if (argc >= 3 && argv[2][0] != '-')
    {
        output_file = argv[2];
        arg_start_idx = 3;
    }
    else
    {
        // Generate output file name from input file name by appending .zypher to it
        char *input_filename = get_full_filename(input_file);
        if (!input_filename)
        {
            fprintf(stderr, "Error: Could not determine input filename for output\n");
            return 1;
        }

        // Allocate memory for the output filename
        output_file = malloc(strlen(input_filename) + 8 + 5); // +8 for ".zypher", +5 for ".php\0"
        if (!output_file)
        {
            fprintf(stderr, "Error: Memory allocation failed\n");
            free(input_filename);
            return 1;
        }

        // Create the output filename with appended .zypher extension
        sprintf(output_file, "%s.zypher", input_filename);
        free(input_filename);

        printf("Output file not specified, using: %s\n", output_file);
    }

    // Parse command line arguments
    for (int i = arg_start_idx; i < argc; i++)
    {
        if (strcmp(argv[i], "--dump") == 0)
        {
            dump_flag = 1;
        }
        else if (strcmp(argv[i], "--validate") == 0)
        {
            validate_flag = 1;
        }
        else
        {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            if (arg_start_idx == 2)
            {
                free(output_file); // Only free if we allocated it
            }
            return 1;
        }
    }

    // Generate the dump output filenames if needed
    char *disassemble_file = NULL;
    char *hexdump_file = NULL;

    if (dump_flag)
    {
        // Get the input filename for appending extensions
        char *input_filename = get_full_filename(input_file);
        if (!input_filename)
        {
            fprintf(stderr, "Error: Could not determine input filename for dump outputs\n");
            if (arg_start_idx == 2)
            {
                free(output_file); // Only free if we allocated it
            }
            return 1;
        }

        // Allocate memory for the output filenames
        disassemble_file = malloc(strlen(input_filename) + 5); // +5 for ".dis\0"
        hexdump_file = malloc(strlen(input_filename) + 5);     // +5 for ".hex\0"

        if (!disassemble_file || !hexdump_file)
        {
            fprintf(stderr, "Error: Memory allocation failed\n");
            free(input_filename);
            free(disassemble_file);
            free(hexdump_file);
            if (arg_start_idx == 2)
            {
                free(output_file); // Only free if we allocated it
            }
            return 1;
        }

        // Create the output filenames with extensions appended to original filename
        sprintf(disassemble_file, "%s.dis", input_filename);
        sprintf(hexdump_file, "%s.hex", input_filename);
        free(input_filename);

        printf("Dump files will be generated as:\n");
        printf("  Disassembly: %s\n", disassemble_file);
        printf("  Hexdump: %s\n", hexdump_file);
    }

    // Initialize PHP embedding
    php_embed_init(argc, argv);

    zend_file_handle file_handle;
    zend_op_array *op_array;

    printf("Processing PHP file: %s\n", input_file);
    zend_stream_init_filename(&file_handle, input_file);
    op_array = zend_compile_file(&file_handle, ZEND_INCLUDE);

    if (op_array)
    {
        printf("Serializing opcodes to: %s\n", output_file);
        serialize_opcodes(op_array, output_file);

        // Export as disassembly if dump is requested
        if (dump_flag && disassemble_file)
        {
            printf("Exporting opcode disassembly to: %s\n", disassemble_file);
            export_opcodes_text(op_array, disassemble_file);
        }

        destroy_op_array(op_array);
        efree(op_array);
        zend_destroy_file_handle(&file_handle);
    }
    else
    {
        fprintf(stderr, "Failed to compile the PHP file: %s\n", input_file);
        zend_destroy_file_handle(&file_handle);
        php_embed_shutdown();

        // Clean up memory if allocated
        free(disassemble_file);
        free(hexdump_file);
        if (arg_start_idx == 2)
        {
            free(output_file); // Only free if we allocated it
        }
        return 1;
    }

    // Shut down PHP embedding
    php_embed_shutdown();

    // Post-processing operations that don't require PHP embed

    // Validate binary format if requested
    if (validate_flag)
    {
        printf("Validating binary opcode file: %s\n", output_file);
        if (validate_opcode_binary(output_file) != 0)
        {
            // Clean up memory if allocated
            free(disassemble_file);
            free(hexdump_file);
            if (arg_start_idx == 2)
            {
                free(output_file); // Only free if we allocated it
            }
            return 1;
        }
    }

    // Generate hexdump if dump is requested
    if (dump_flag && hexdump_file)
    {
        printf("Generating hexdump: %s\n", hexdump_file);
        hex_dump(output_file, hexdump_file);
    }

    printf("Processing completed successfully.\n");

    // Clean up memory if allocated
    free(disassemble_file);
    free(hexdump_file);
    if (arg_start_idx == 2)
    {
        free(output_file); // Only free if we allocated it
    }
    return 0;
}
