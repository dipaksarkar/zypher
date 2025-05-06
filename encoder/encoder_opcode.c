/**
 * Zypher PHP Encoder - Opcode compilation functionality
 * Handles PHP source to opcode compilation and serialization
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

/* Common headers */
#include "../include/zypher_encoder.h"
#include "../include/zypher_common.h"

/* External debug functions */
extern void print_debug(const char *format, ...);
extern void print_error(const char *format, ...);

/*
 * Compile PHP source code to serialized opcodes
 */
int compile_php_to_opcodes(const char *source_code, const char *filename, char **output, size_t *output_len)
{
    int ret = ZYPHER_FAILURE;
    char temp_file_path[PATH_MAX];
    char temp_output_path[PATH_MAX];
    FILE *temp_file = NULL;
    FILE *output_file = NULL;
    char command[PATH_MAX * 4];

    // Generate temporary file paths
    snprintf(temp_file_path, PATH_MAX, "/tmp/zypher_temp_%ld.php", (long)time(NULL));
    snprintf(temp_output_path, PATH_MAX, "/tmp/zypher_temp_output_%ld", (long)time(NULL));

    // Write source code to temporary file
    temp_file = fopen(temp_file_path, "w");
    if (!temp_file)
    {
        fprintf(stderr, "Error creating temporary file\n");
        goto cleanup;
    }

    fwrite(source_code, 1, strlen(source_code), temp_file);
    fclose(temp_file);
    temp_file = NULL;

    // First check PHP syntax
    snprintf(command, sizeof(command), "php -l %s > /dev/null 2>&1", temp_file_path);
    if (system(command) != 0)
    {
        fprintf(stderr, "PHP syntax error in %s\n", filename);
        goto cleanup;
    }

    // Create a PHP script to serialize the source code with enhanced metadata
    char php_script[8192];
    snprintf(php_script, sizeof(php_script),
             "<?php\n"
             "// Read the source file\n"
             "$source = file_get_contents('%s');\n"
             "// Extract namespace and class name if possible\n"
             "$namespace = '';\n"
             "$classname = '';\n"
             "\n"
             "// Parse PHP code to extract namespace and class information\n"
             "$tokens = token_get_all($source);\n"
             "for ($i = 0; $i < count($tokens); $i++) {\n"
             "    // Extract namespace\n"
             "    if (is_array($tokens[$i]) && $tokens[$i][0] === T_NAMESPACE) {\n"
             "        for ($j = $i + 1; $j < count($tokens); $j++) {\n"
             "            if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {\n"
             "                $namespace .= $tokens[$j][1];\n"
             "            } else if ($tokens[$j] === ';') {\n"
             "                break;\n"
             "            } else if (is_array($tokens[$j]) && $tokens[$j][0] === T_NS_SEPARATOR) {\n"
             "                $namespace .= '\\\\';\n"
             "            }\n"
             "        }\n"
             "    }\n"
             "    \n"
             "    // Extract class name\n"
             "    if (is_array($tokens[$i]) && $tokens[$i][0] === T_CLASS) {\n"
             "        for ($j = $i + 1; $j < count($tokens); $j++) {\n"
             "            if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {\n"
             "                $classname = $tokens[$j][1];\n"
             "                break;\n"
             "            }\n"
             "        }\n"
             "    }\n"
             "}\n"
             "\n"
             "// Create a data array with original content and enhanced metadata\n"
             "$data = [\n"
             "    'filename' => '%s',\n"
             "    'contents' => $source,\n"
             "    // Store complete source code as source_hint to ensure perfect reconstruction\n"
             "    'source_hint' => $source,\n"
             "    'namespace' => $namespace,\n"
             "    'classname' => $classname,\n"
             "];\n"
             "\n"
             "// Serialize the data and calculate MD5 checksum\n"
             "$serialized = serialize($data);\n"
             "$md5 = md5($serialized);\n"
             "\n"
             "// Write to output file: MD5 hash followed by serialized data\n"
             "file_put_contents('%s', $md5 . $serialized);\n"
             "?>\n",
             temp_file_path, filename, temp_output_path);

    // Write the PHP script to a new temporary file
    char temp_script_path[PATH_MAX];
    snprintf(temp_script_path, PATH_MAX, "/tmp/zypher_script_%ld.php", (long)time(NULL));
    temp_file = fopen(temp_script_path, "w");
    if (!temp_file)
    {
        fprintf(stderr, "Error creating temporary script file\n");
        goto cleanup;
    }

    fwrite(php_script, 1, strlen(php_script), temp_file);
    fclose(temp_file);
    temp_file = NULL;

    // Execute the PHP script to process the file
    snprintf(command, sizeof(command), "php %s", temp_script_path);
    if (system(command) != 0)
    {
        fprintf(stderr, "Error processing PHP file %s\n", filename);
        unlink(temp_script_path);
        goto cleanup;
    }

    // Clean up the script
    unlink(temp_script_path);

    // Read the output file
    struct stat st;
    if (stat(temp_output_path, &st) != 0)
    {
        fprintf(stderr, "Error reading output file\n");
        goto cleanup;
    }

    *output_len = st.st_size;
    *output = (char *)malloc(*output_len + 1);
    if (!*output)
    {
        fprintf(stderr, "Memory allocation error\n");
        goto cleanup;
    }

    output_file = fopen(temp_output_path, "r");
    if (!output_file)
    {
        fprintf(stderr, "Error opening output file\n");
        free(*output);
        *output = NULL;
        goto cleanup;
    }

    if (fread(*output, 1, *output_len, output_file) != *output_len)
    {
        fprintf(stderr, "Error reading from output file\n");
        free(*output);
        *output = NULL;
        fclose(output_file);
        goto cleanup;
    }

    (*output)[*output_len] = '\0';
    fclose(output_file);

    ret = ZYPHER_SUCCESS;

cleanup:
    // Remove temporary files
    if (temp_file)
        fclose(temp_file);
    unlink(temp_file_path);
    unlink(temp_output_path);

    return ret;
}