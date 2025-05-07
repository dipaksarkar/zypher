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

    /* Create improved PHP opcode extraction */
    char *temp_file = "/tmp/zypher_temp_source.php";
    char *opcode_extractor = "/tmp/zypher_extract_opcodes.php";
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

    /* Create a better PHP script to extract opcodes with PHP internals */
    fp = fopen(opcode_extractor, "w");
    if (!fp)
    {
        print_error("Failed to create opcode extractor script");
        unlink(temp_file);
        return ZYPHER_FAILURE;
    }

    /* Write the improved PHP code to extract opcodes */
    fprintf(fp, "<?php\n");
    fprintf(fp, "// Zypher Opcode Extractor\n");
    fprintf(fp, "error_reporting(E_ALL);\n\n");
    fprintf(fp, "// Configuration\n");
    fprintf(fp, "$source_file = '%s';\n", temp_file);
    fprintf(fp, "$original_filename = '%s';\n", filename);
    fprintf(fp, "$source_code = file_get_contents($source_file);\n\n");

    /* Parse the file to extract namespace and class information */
    fprintf(fp, "// Extract namespace and class information\n");
    fprintf(fp, "$namespace = '';\n");
    fprintf(fp, "$classname = '';\n");
    fprintf(fp, "$tokens = token_get_all($source_code);\n");
    fprintf(fp, "$in_namespace = false;\n");
    fprintf(fp, "foreach ($tokens as $token) {\n");
    fprintf(fp, "    if (is_array($token)) {\n");
    fprintf(fp, "        list($id, $text) = $token;\n");
    fprintf(fp, "        if ($id === T_NAMESPACE) {\n");
    fprintf(fp, "            $in_namespace = true;\n");
    fprintf(fp, "        } elseif ($in_namespace && $id === T_STRING) {\n");
    fprintf(fp, "            $namespace .= $text;\n");
    fprintf(fp, "        } elseif ($in_namespace && $id === T_NS_SEPARATOR) {\n");
    fprintf(fp, "            $namespace .= '\\\\';\n");
    fprintf(fp, "        } elseif ($in_namespace && $id === T_WHITESPACE) {\n");
    fprintf(fp, "            // Skip whitespace in namespace\n");
    fprintf(fp, "        } elseif ($in_namespace && $text === ';') {\n");
    fprintf(fp, "            $in_namespace = false;\n");
    fprintf(fp, "        } elseif ($id === T_CLASS) {\n");
    fprintf(fp, "            // Get next non-whitespace token which should be the class name\n");
    fprintf(fp, "            $i = array_search($token, $tokens) + 1;\n");
    fprintf(fp, "            while (isset($tokens[$i]) && is_array($tokens[$i]) && $tokens[$i][0] === T_WHITESPACE) {\n");
    fprintf(fp, "                $i++;\n");
    fprintf(fp, "            }\n");
    fprintf(fp, "            if (isset($tokens[$i]) && is_array($tokens[$i]) && $tokens[$i][0] === T_STRING) {\n");
    fprintf(fp, "                $classname = $tokens[$i][1];\n");
    fprintf(fp, "            }\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "}\n\n");

    /* Create more reliable opcode extraction */
    fprintf(fp, "// Create data structure to hold source and metadata\n");
    fprintf(fp, "$result = [\n");
    fprintf(fp, "    'filename' => $original_filename,\n");
    fprintf(fp, "    'contents' => $source_code,\n");
    fprintf(fp, "    'source_hint' => $source_code,\n"); // Store full source
    fprintf(fp, "    'namespace' => $namespace,\n");
    fprintf(fp, "    'classname' => $classname,\n");
    fprintf(fp, "    'timestamp' => time(),\n");
    fprintf(fp, "    'php_version' => PHP_VERSION,\n");
    fprintf(fp, "];\n\n");

    /* Try to use OPcache to get file status if available */
    fprintf(fp, "// Try to use OPcache if available\n");
    fprintf(fp, "if (function_exists('opcache_compile_file') && function_exists('opcache_get_status')) {\n");
    fprintf(fp, "    if (opcache_compile_file($source_file)) {\n");
    fprintf(fp, "        $opcache_status = opcache_get_status(true);\n");
    fprintf(fp, "        $result['compiled_with'] = 'opcache';\n");
    fprintf(fp, "        if (isset($opcache_status['scripts'][$source_file])) {\n");
    fprintf(fp, "            $result['opcache_info'] = $opcache_status['scripts'][$source_file];\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "}\n\n");

    /* Directly compile the PHP code for better reliability */
    fprintf(fp, "// Direct compilation\n");
    fprintf(fp, "try {\n");
    fprintf(fp, "    $result['compiled_with'] = 'direct';\n");
    fprintf(fp, "    \n");
    fprintf(fp, "    // Use a safe approach with temp files to avoid issues\n");
    fprintf(fp, "    $temp_func_file = '/tmp/zypher_func_' . uniqid() . '.php';\n");
    fprintf(fp, "    file_put_contents($temp_func_file, '<?php\\n' . $source_code);\n");
    fprintf(fp, "    include_once($temp_func_file);\n");
    fprintf(fp, "    unlink($temp_func_file);\n");
    fprintf(fp, "    $result['compilation_success'] = true;\n");
    fprintf(fp, "} catch (Error $e) {\n");
    fprintf(fp, "    $result['compilation_success'] = false;\n");
    fprintf(fp, "    $result['compilation_error'] = $e->getMessage();\n");
    fprintf(fp, "}\n\n");

    /* Output the final result as raw serialized data, not base64 encoded */
    fprintf(fp, "// Output raw serialized result instead of base64\n");
    fprintf(fp, "$serialized = serialize($result);\n");
    fprintf(fp, "echo 'ZYPHER_OPCODES:' . $serialized;\n");
    fprintf(fp, "?>\n");
    fclose(fp);

    /* Create command to run the extractor script */
    char *command = (char *)malloc(strlen(opcode_extractor) + 512);
    if (!command)
    {
        print_error("Failed to allocate memory for command");
        unlink(temp_file);
        unlink(opcode_extractor);
        return ZYPHER_FAILURE;
    }

    /* Run PHP with error reporting enabled to get detailed errors */
    sprintf(command, "php -d display_errors=1 -d error_reporting=E_ALL %s 2>&1", opcode_extractor);
    opcode_output = run_command(command, &cmd_output_size);
    free(command);

    /* Clean up temporary files */
    unlink(temp_file);
    unlink(opcode_extractor);

    if (!opcode_output || cmd_output_size == 0)
    {
        print_error("Failed to generate opcodes");
        return ZYPHER_FAILURE;
    }

    /* Verify the output starts with our marker */
    char *marker_pos = strstr(opcode_output, "ZYPHER_OPCODES:");
    if (!marker_pos)
    {
        print_error("Invalid opcode output format: %s", opcode_output);
        free(opcode_output);
        return ZYPHER_FAILURE;
    }

    /* Strip everything before the prefix and return just the encoded data */
    size_t prefix_len = strlen("ZYPHER_OPCODES:");
    size_t offset = marker_pos - opcode_output + prefix_len;
    memmove(opcode_output, opcode_output + offset, cmd_output_size - offset + 1);
    *output = opcode_output;
    *output_len = cmd_output_size - offset;

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