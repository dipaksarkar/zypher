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
#include <main/php.h>
#include <main/php_main.h>
#include <Zend/zend.h>
#include <Zend/zend_compile.h>
#include <Zend/zend_execute.h>
#include <Zend/zend_interfaces.h>
#include <Zend/zend_smart_str.h>
#include <Zend/zend_hash.h>
#include <ext/standard/php_var.h>
#include <ext/standard/php_smart_string.h>
#endif

/* Forward declarations */
extern void print_debug(const char *format, ...);
extern void print_error(const char *format, ...);
extern char *run_command(const char *command, size_t *output_size);

/* Global PHP embedding state */
#ifdef HAVE_EMBED
static int php_initialized = 0;
static php_stream *output_stream = NULL;
static zend_bool output_started = 0;

/* Output handler to capture PHP output */
static size_t zypher_output_handler(const char *str, size_t str_length)
{
    if (output_stream) {
        php_stream_write(output_stream, str, str_length);
    }
    return str_length;
}

/* Initialize PHP embed SAPI once */
int initialize_php_embed() {
    if (php_initialized) {
        return ZYPHER_SUCCESS;
    }
    
    /* Initialize PHP */
    php_embed_init(0, NULL);
    php_initialized = 1;
    
    /* Register shutdown function */
    atexit(php_embed_shutdown);
    
    print_debug("PHP embedding initialized successfully");
    return ZYPHER_SUCCESS;
}

/* Start capturing PHP output */
int start_output_capture() {
    if (output_started) {
        return ZYPHER_SUCCESS;
    }
    
    /* Create a memory stream to capture output */
    output_stream = php_stream_memory_create(TEMP_STREAM_DEFAULT);
    if (!output_stream) {
        print_error("Failed to create memory stream for output capture");
        return ZYPHER_FAILURE;
    }
    
    /* Set our output handler */
    php_output_start_user(zypher_output_handler, NULL, 0);
    output_started = 1;
    
    return ZYPHER_SUCCESS;
}

/* End output capture and return the captured output */
char *end_output_capture(size_t *length) {
    char *buffer = NULL;
    
    if (!output_started || !output_stream) {
        *length = 0;
        return NULL;
    }
    
    /* End output capturing */
    php_output_end();
    output_started = 0;
    
    /* Get the content from memory stream */
    *length = php_stream_tell(output_stream);
    if (*length > 0) {
        buffer = (char *)malloc(*length + 1);
        if (buffer) {
            php_stream_rewind(output_stream);
            php_stream_read(output_stream, buffer, *length);
            buffer[*length] = '\0';
        }
    }
    
    /* Close the stream */
    php_stream_close(output_stream);
    output_stream = NULL;
    
    return buffer;
}
#endif

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

/* Extract identifiers and symbols from PHP code for namespace field */
char *extract_identifiers(const char *source_code) {
    if (!source_code) {
        return NULL;
    }
    
    /* Extract identifiers using token_get_all */
    char *temp_file = "/tmp/zypher_temp_identifiers.php";
    FILE *fp = fopen(temp_file, "w");
    if (!fp) {
        return NULL;
    }
    
    /* Write a PHP script that extracts identifiers */
    fprintf(fp, "<?php\n");
    fprintf(fp, "$source = file_get_contents('php://stdin');\n");
    fprintf(fp, "$tokens = token_get_all($source);\n");
    fprintf(fp, "$identifiers = [];\n");
    fprintf(fp, "foreach ($tokens as $token) {\n");
    fprintf(fp, "    if (is_array($token)) {\n");
    fprintf(fp, "        if ($token[0] === T_STRING || $token[0] === T_CLASS || \n");
    fprintf(fp, "            $token[0] === T_FUNCTION || $token[0] === T_VARIABLE || \n");
    fprintf(fp, "            $token[0] === T_NAMESPACE || $token[0] === T_CONST) {\n");
    fprintf(fp, "            $identifiers[] = $token[1];\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "}\n");
    fprintf(fp, "echo implode('', $identifiers);\n");
    fprintf(fp, "?>");
    fclose(fp);
    
    /* Run the script */
    char command[512];
    sprintf(command, "php %s", temp_file);
    
    FILE *pipe = popen(command, "w");
    if (!pipe) {
        unlink(temp_file);
        return NULL;
    }
    
    /* Write the source code to the script's stdin */
    fwrite(source_code, 1, strlen(source_code), pipe);
    fclose(pipe);
    
    /* Run the command to get the identifiers */
    size_t output_size = 0;
    char *identifiers = run_command(command, &output_size);
    
    /* Clean up */
    unlink(temp_file);
    
    return identifiers ? identifiers : strdup("");
}

/* Obfuscate opcode data before encoding to make reverse engineering more difficult */
int obfuscate_opcode_data(char *data, size_t data_len, const char *namespace_hint)
{
    if (!data || data_len == 0 || !namespace_hint) {
        return ZYPHER_FAILURE;
    }
    
    // Create a deterministic but unpredictable transformation key based on namespace hint
    unsigned char transform_key[32] = {0};
    PHP_MD5_CTX context;
    
    PHP_MD5Init(&context);
    PHP_MD5Update(&context, (unsigned char *)namespace_hint, strlen(namespace_hint));
    PHP_MD5Update(&context, (unsigned char *)ZYPHER_OBFUSCATE_SALT, strlen(ZYPHER_OBFUSCATE_SALT));
    PHP_MD5Final(transform_key, &context);
    
    // Additional 16 bytes from SHA-1
    PHP_SHA1_CTX sha_context;
    PHP_SHA1Init(&sha_context);
    PHP_SHA1Update(&sha_context, (unsigned char *)namespace_hint, strlen(namespace_hint));
    PHP_SHA1Update(&sha_context, (unsigned char *)ZYPHER_OBFUSCATE_SALT, strlen(ZYPHER_OBFUSCATE_SALT));
    PHP_SHA1Final(transform_key + 16, &sha_context);
    
    print_debug("Obfuscating opcode data with transformation key");
    
    // Apply XOR transformation with sliding window
    for (size_t i = 0; i < data_len; i++) {
        unsigned char key_byte = transform_key[i % 32];
        unsigned char prev_byte = (i > 0) ? data[i-1] : 0;
        
        // XOR with key and previous byte for avalanche effect
        data[i] ^= (key_byte ^ (prev_byte >> 4));
        
        // Every 64 bytes, rotate the key
        if ((i % 64) == 63) {
            unsigned char tmp = transform_key[0];
            for (int j = 0; j < 31; j++) {
                transform_key[j] = transform_key[j+1];
            }
            transform_key[31] = tmp;
        }
    }
    
    return ZYPHER_SUCCESS;
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
    /* Initialize PHP embedding if needed */
    if (initialize_php_embed() != ZYPHER_SUCCESS) {
        print_error("Failed to initialize PHP embedding");
        return ZYPHER_FAILURE;
    }

    /* Start a new request */
    if (php_request_startup() != SUCCESS) {
        print_error("Failed to start PHP request");
        return ZYPHER_FAILURE;
    }

    /* Start output capture */
    start_output_capture();

    /* Create a PHP array to hold our data */
    zval data_array;
    array_init(&data_array);
    
    /* Add source file info */
    add_assoc_string(&data_array, "filename", (char *)filename);
    add_assoc_string(&data_array, "contents", (char *)source_code);
    
    /* Add source code hash */
    char source_md5[33];
    PHP_MD5_CTX context;
    unsigned char digest[16];
    
    PHP_MD5Init(&context);
    PHP_MD5Update(&context, (unsigned char *)source_code, strlen(source_code));
    PHP_MD5Final(digest, &context);
    
    for (int i = 0; i < 16; i++) {
        sprintf(&source_md5[i * 2], "%02x", (unsigned int)digest[i]);
    }
    source_md5[32] = '\0';
    
    add_assoc_string(&data_array, "source_hint", (char *)source_code);
    
    /* Add namespace and symbol information for obfuscation */
    char *identifiers = extract_identifiers(source_code);
    if (identifiers) {
        add_assoc_string(&data_array, "namespace", identifiers);
        free(identifiers);
    } else {
        add_assoc_string(&data_array, "namespace", "");
    }
    
    /* Try to extract classname from the code */
    zend_string *classname = NULL;
    zend_class_entry *ce = NULL;
    
    /* Set up file handle for our source code */
    zend_file_handle file_handle;
    memset(&file_handle, 0, sizeof(file_handle));
    file_handle.type = ZEND_HANDLE_STRING;
    file_handle.filename = filename;
    file_handle.opened_path = NULL;
    file_handle.free_filename = 0;
    file_handle.handle.stream.handle = NULL;
    file_handle.handle.string.val = (char *)source_code;
    file_handle.handle.string.len = strlen(source_code);

    /* Try to compile the source code */
    zend_op_array *op_array = zend_compile_file(&file_handle, ZEND_INCLUDE);
    
    if (op_array) {
        /* Look for classes defined in the code */
        HashTable *class_table = CG(class_table);
        zend_string *key;
        zend_class_entry *ce_temp;
        
        ZEND_HASH_FOREACH_STR_KEY_PTR(class_table, key, ce_temp) {
            if (ce_temp->type == ZEND_USER_CLASS) {
                classname = zend_string_copy(key);
                ce = ce_temp;
                break;
            }
        } ZEND_HASH_FOREACH_END();
        
        if (classname) {
            add_assoc_string(&data_array, "classname", ZSTR_VAL(classname));
            zend_string_release(classname);
        } else {
            add_assoc_string(&data_array, "classname", "");
        }
        
        /* Add timestamp and PHP version */
        add_assoc_long(&data_array, "timestamp", time(NULL));
        add_assoc_string(&data_array, "php_version", PHP_VERSION);
        
        /* Add compilation information */
        add_assoc_string(&data_array, "compiled_with", "direct");
        add_assoc_bool(&data_array, "compilation_success", 1);
        
        /* Clean up */
        destroy_op_array(op_array);
        efree(op_array);
    } else {
        /* Compilation failed, capture the error message */
        add_assoc_string(&data_array, "classname", "");
        add_assoc_long(&data_array, "timestamp", time(NULL));
        add_assoc_string(&data_array, "php_version", PHP_VERSION);
        add_assoc_string(&data_array, "compiled_with", "direct");
        add_assoc_bool(&data_array, "compilation_success", 0);
        
        /* Get the last error message */
        zval *error = zend_get_exception_base(NULL);
        if (error) {
            zval *message = zend_read_property(Z_OBJCE_P(error), error, "message", sizeof("message")-1, 0, NULL);
            if (message && Z_TYPE_P(message) == IS_STRING) {
                add_assoc_string(&data_array, "compilation_error", Z_STRVAL_P(message));
            } else {
                add_assoc_string(&data_array, "compilation_error", "Unknown compilation error");
            }
        } else {
            add_assoc_string(&data_array, "compilation_error", "Syntax error");
        }
    }
    
    /* Serialize the data array */
    php_serialize_data_t var_hash;
    smart_str buf = {0};
    
    PHP_VAR_SERIALIZE_INIT(var_hash);
    php_var_serialize(&buf, &data_array, &var_hash);
    PHP_VAR_SERIALIZE_DESTROY(var_hash);
    
    /* End the request */
    php_request_shutdown(NULL);
    
    /* Extract serialized data */
    if (buf.s) {
        *output = estrndup(ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
        *output_len = ZSTR_LEN(buf.s);
        smart_str_free(&buf);
        
        /* Clean up */
        zval_ptr_dtor(&data_array);
        
        print_debug("Successfully compiled and serialized opcodes (%zu bytes)", *output_len);
        return ZYPHER_SUCCESS;
    } else {
        print_error("Failed to serialize PHP data");
        zval_ptr_dtor(&data_array);
        return ZYPHER_FAILURE;
    }
#else
    /* No PHP embedding - use external PHP process as fallback */
    char *temp_file = "/tmp/zypher_temp_compile.php";
    FILE *fp = NULL;
    char command[1024];
    size_t cmd_output_size = 0;

    /* Write source to a temporary file */
    fp = fopen(temp_file, "w");
    if (!fp) {
        print_error("Failed to create temporary file for compilation");
        return ZYPHER_FAILURE;
    }
    
    fwrite(source_code, 1, strlen(source_code), fp);
    fclose(fp);
    
    /* Create a PHP script that will serialize the necessary information */
    char *script_file = "/tmp/zypher_compile_script.php";
    fp = fopen(script_file, "w");
    if (!fp) {
        print_error("Failed to create script file");
        unlink(temp_file);
        return ZYPHER_FAILURE;
    }
    
    /* Write the compilation script */
    fprintf(fp, "<?php\n");
    fprintf(fp, "$source_file = '%s';\n", temp_file);
    fprintf(fp, "$source_code = file_get_contents($source_file);\n");
    fprintf(fp, "$filename = '%s';\n", filename);
    fprintf(fp, "\n");
    fprintf(fp, "// Create the structure\n");
    fprintf(fp, "$data = array(\n");
    fprintf(fp, "  'filename' => $filename,\n");
    fprintf(fp, "  'contents' => $source_code,\n");
    fprintf(fp, "  'source_hint' => $source_code,\n");
    fprintf(fp, "  'namespace' => '',\n");  // This would need more logic to extract
    fprintf(fp, "  'classname' => '',\n");  // This would need more logic to extract
    fprintf(fp, "  'timestamp' => time(),\n");
    fprintf(fp, "  'php_version' => PHP_VERSION,\n");
    fprintf(fp, "  'compiled_with' => 'external',\n");
    fprintf(fp, "  'compilation_success' => false,\n");
    fprintf(fp, "  'compilation_error' => 'Direct compilation not available (no PHP embed)',\n");
    fprintf(fp, ");\n");
    fprintf(fp, "\n");
    fprintf(fp, "// Extract identifiers for namespace\n");
    fprintf(fp, "$tokens = token_get_all($source_code);\n");
    fprintf(fp, "$identifiers = array();\n");
    fprintf(fp, "foreach ($tokens as $token) {\n");
    fprintf(fp, "  if (is_array($token) && in_array($token[0], array(T_STRING, T_CLASS, T_FUNCTION, T_VARIABLE))) {\n");
    fprintf(fp, "    $identifiers[] = $token[1];\n");
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");
    fprintf(fp, "$data['namespace'] = implode('', $identifiers);\n");
    fprintf(fp, "\n");
    fprintf(fp, "// Try to determine class name\n");
    fprintf(fp, "foreach ($tokens as $i => $token) {\n");
    fprintf(fp, "  if (is_array($token) && $token[0] === T_CLASS) {\n");
    fprintf(fp, "    // Skip whitespace\n");
    fprintf(fp, "    $j = $i + 1;\n");
    fprintf(fp, "    while (isset($tokens[$j]) && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {\n");
    fprintf(fp, "      $j++;\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "    // Get class name\n");
    fprintf(fp, "    if (isset($tokens[$j]) && is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {\n");
    fprintf(fp, "      $data['classname'] = $tokens[$j][1];\n");
    fprintf(fp, "      break;\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");
    fprintf(fp, "\n");
    fprintf(fp, "// Try to verify syntax\n");
    fprintf(fp, "try {\n");
    fprintf(fp, "  $result = eval('return true; ?>' . $source_code);\n");
    fprintf(fp, "  if ($result !== false) {\n");
    fprintf(fp, "    $data['compilation_success'] = true;\n");
    fprintf(fp, "    $data['compilation_error'] = '';\n");
    fprintf(fp, "  }\n");
    fprintf(fp, "} catch (ParseError $e) {\n");
    fprintf(fp, "  $data['compilation_error'] = $e->getMessage();\n");
    fprintf(fp, "}\n");
    fprintf(fp, "\n");
    fprintf(fp, "// Output serialized data\n");
    fprintf(fp, "echo serialize($data);\n");
    fprintf(fp, "?>\n");
    fclose(fp);
    
    /* Execute the compilation script */
    sprintf(command, "php %s", script_file);
    *output = run_command(command, &cmd_output_size);
    *output_len = cmd_output_size;
    
    /* Clean up temporary files */
    unlink(temp_file);
    unlink(script_file);
    
    if (*output && *output_len > 0) {
        print_debug("Successfully created opcodes using external PHP process (%zu bytes)", *output_len);
        return ZYPHER_SUCCESS;
    } else {
        print_error("Failed to compile PHP file using external process");
        free(*output);
        *output = NULL;
        *output_len = 0;
        return ZYPHER_FAILURE;
    }
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