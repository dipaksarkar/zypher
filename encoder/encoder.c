/**
 * Zypher PHP Encoder - Core encoding functionality
 * Responsible for PHP compilation, opcode extraction, and encryption
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <libgen.h>

#include "php.h"
#include "php_ini.h"
#include "ext/standard/base64.h"
#include "ext/standard/md5.h"
#include "ext/standard/info.h"
#include "ext/standard/php_var.h"
#include "Zend/zend_compile.h"
#include "Zend/zend_execute.h"
#include "Zend/zend_vm.h"
#include "Zend/zend_operators.h"

#include "../include/zypher_encoder.h"
#include "../build/zypher_master_key.h"

/* Function to initialize the encoder */
int zypher_encoder_init(void)
{
    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Seed the random number generator */
    RAND_poll();

    print_debug("Encoder initialized with master key: %s", ZYPHER_MASTER_KEY);
    return 1;
}

/* Function to shutdown and clean up resources */
void zypher_encoder_shutdown(void)
{
    /* Clean up OpenSSL */
    EVP_cleanup();
    ERR_free_strings();

    print_debug("Encoder shutdown");
}

/* Function to read file contents */
char *read_file(const char *filename, size_t *size)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        print_error("Could not open file: %s", filename);
        return NULL;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    if (file_size <= 0)
    {
        print_error("Empty file: %s", filename);
        fclose(fp);
        return NULL;
    }

    /* Allocate memory for file contents */
    char *buffer = (char *)malloc(file_size + 1);
    if (!buffer)
    {
        print_error("Memory allocation failed");
        fclose(fp);
        return NULL;
    }

    /* Read file contents */
    size_t bytes_read = fread(buffer, 1, file_size, fp);
    fclose(fp);

    if (bytes_read != file_size)
    {
        print_error("Failed to read entire file");
        free(buffer);
        return NULL;
    }

    /* Null-terminate the buffer */
    buffer[file_size] = '\0';

    if (size)
    {
        *size = file_size;
    }

    return buffer;
}

/* Function to write data to a file */
int write_file(const char *filename, const char *data, size_t size)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp)
    {
        print_error("Could not open file for writing: %s", filename);
        return 0;
    }

    size_t bytes_written = fwrite(data, 1, size, fp);
    fclose(fp);

    if (bytes_written != size)
    {
        print_error("Failed to write entire file");
        return 0;
    }

    return 1;
}

/* Helper function for MD5 hash calculation */
static char *md5_hash(const char *input, size_t input_len)
{
    PHP_MD5_CTX context;
    unsigned char digest[16];
    char *output = malloc(33); /* 32 hex chars + null terminator */
    int i;

    PHP_MD5Init(&context);
    PHP_MD5Update(&context, (const unsigned char *)input, input_len);
    PHP_MD5Final(digest, &context);

    for (i = 0; i < 16; i++)
    {
        sprintf(&output[i * 2], "%02x", digest[i]);
    }
    output[32] = '\0';

    return output;
}

/* Function to calculate content checksum */
void calculate_checksum(const char *content, size_t length, char *output)
{
    char *md5 = md5_hash(content, length);
    strcpy(output, md5);
    free(md5);

    print_debug("Calculated checksum: %s", output);
}

/* Function to compile PHP source to opcodes */
zval *compile_php_to_opcodes(const char *source, size_t source_len, const char *filename)
{
    zval *opcodes;
    zend_string *code;
    zend_file_handle file_handle;
    zend_op_array *op_array;
    zval retval;

    print_debug("Compiling PHP source to opcodes (%zu bytes)", source_len);

    /* Create a PHP string from source */
    code = zend_string_init(source, source_len, 0);

    /* Set up a file handle structure */
    memset(&file_handle, 0, sizeof(file_handle));
    file_handle.type = ZEND_HANDLE_STRING;
    file_handle.filename = (char *)filename;
    file_handle.handle.str.start = ZSTR_VAL(code);
    file_handle.handle.str.length = ZSTR_LEN(code);
    file_handle.free_filename = 0;

    /* Compile the PHP code */
    op_array = zend_compile_file(&file_handle, ZEND_INCLUDE);

    /* Clean up string */
    zend_string_release(code);

    if (!op_array)
    {
        print_error("Compilation failed");
        return NULL;
    }

    /* Create a zval to hold the opcodes array */
    opcodes = (zval *)malloc(sizeof(zval));
    array_init(opcodes);

    /* Extract opcode information - store the opcode array basics */
    add_assoc_long(opcodes, "last_var", op_array->last_var);
    add_assoc_long(opcodes, "T", op_array->T);
    add_assoc_long(opcodes, "last_literal", op_array->last_literal);
    add_assoc_string(opcodes, "filename", ZSTR_VAL(op_array->filename));
    add_assoc_long(opcodes, "line_start", op_array->line_start);
    add_assoc_long(opcodes, "line_end", op_array->line_end);

    /* Add filename and class/namespace info for better context in loader */
    char *bname = basename((char *)filename);
    add_assoc_string(opcodes, "orig_filename", bname);

    /* Create a nested array for opcodes */
    zval opcodes_array;
    array_init(&opcodes_array);

    /* Get all the opcodes */
    zend_op *opline = op_array->opcodes;
    zend_op *end = opline + op_array->last;

    for (; opline < end; opline++)
    {
        zval op;
        array_init(&op);

        /* Store opcode and operands */
        add_assoc_long(&op, "opcode", opline->opcode);
        add_assoc_long(&op, "op1_type", opline->op1_type);
        add_assoc_long(&op, "op2_type", opline->op2_type);
        add_assoc_long(&op, "result_type", opline->result_type);

        /* Add op to opcodes array */
        add_next_index_zval(&opcodes_array, &op);
    }

    /* Add opcodes array to return value */
    add_assoc_zval(opcodes, "opcodes", &opcodes_array);

    /* Clean up op_array */
    destroy_op_array(op_array);
    efree(op_array);

    print_debug("Successfully compiled PHP source to opcodes");

    return opcodes;
}

/* Function to serialize opcodes to binary format */
char *serialize_opcodes(zval *opcodes, size_t *serialized_len)
{
    smart_str buf = {0};
    php_serialize_data_t var_hash;

    print_debug("Serializing opcodes");

    PHP_VAR_SERIALIZE_INIT(var_hash);
    php_var_serialize(&buf, opcodes, &var_hash);
    PHP_VAR_SERIALIZE_DESTROY(var_hash);

    /* Check for successful serialization */
    if (!buf.s)
    {
        print_error("Serialization failed");
        return NULL;
    }

    /* Extract result */
    char *result = estrndup(ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
    *serialized_len = ZSTR_LEN(buf.s);

    /* Clean up */
    smart_str_free(&buf);

    print_debug("Serialized opcodes: %zu bytes", *serialized_len);

    return result;
}

/* Function to generate file-specific encryption key */
char *generate_file_key(const char *master_key, const char *filename, int iterations)
{
    unsigned char digest[32]; /* SHA-256 produces 32 bytes */
    char salt[100];
    char *filename_md5;
    char *output_key = (char *)malloc(65); /* 64 hex chars + null terminator */

    print_debug("Generating file-specific key for '%s'", filename);

    /* Use only basename for key derivation to allow moving files */
    char *bname = basename((char *)filename);

    /* Create salt based on filename MD5 hash - MUST MATCH LOADER IMPLEMENTATION */
    filename_md5 = md5_hash(bname, strlen(bname));
    snprintf(salt, sizeof(salt), "ZypherSalt-%s", filename_md5);
    print_debug("Using salt: %s", salt);
    free(filename_md5);

    /* Initial HMAC */
    unsigned char *derived_key = malloc(32);
    unsigned int derived_len = 32;

    /* Combine filename and salt exactly like PHP would */
    char *combined_data = malloc(strlen(bname) + strlen(salt) + 1);
    strcpy(combined_data, bname);
    strcat(combined_data, salt);

    /* Initial HMAC */
    HMAC(EVP_sha256(), master_key, strlen(master_key),
         (const unsigned char *)combined_data, strlen(combined_data),
         derived_key, &derived_len);

    free(combined_data);

    /* Perform iterations to strengthen the key */
    for (int i = 0; i < iterations; i++)
    {
        /* Create buffer with derived key + salt + iteration byte */
        unsigned char *buffer = malloc(32 + strlen(salt) + 1);
        unsigned int buffer_len = 0;

        /* Combine current key and salt */
        memcpy(buffer, derived_key, 32);
        buffer_len += 32;

        /* Add salt */
        memcpy(buffer + buffer_len, salt, strlen(salt));
        buffer_len += strlen(salt);

        /* Add iteration counter as a byte */
        buffer[buffer_len++] = (unsigned char)(i & 0xFF);

        /* Perform HMAC */
        HMAC(EVP_sha256(), master_key, strlen(master_key),
             buffer, buffer_len, derived_key, &derived_len);

        free(buffer);
    }

    /* Convert to hex string */
    for (int i = 0; i < 32; i++)
    {
        sprintf(output_key + (i * 2), "%02x", derived_key[i]);
    }
    output_key[64] = '\0';

    free(derived_key);

    print_debug("Generated file key: %s", output_key);
    return output_key;
}

/* Function to encrypt serialized opcodes */
char *encrypt_opcodes(char *serialized, size_t serialized_len,
                      zypher_encoding_context *ctx, const char *filename,
                      size_t *encrypted_len)
{
    EVP_CIPHER_CTX *cipher_ctx;
    int outlen, tmplen;
    char *encrypted;
    char checksum[33];

    print_debug("Encrypting serialized opcodes (%zu bytes)", serialized_len);

    /* Calculate checksum for data validation */
    calculate_checksum(serialized, serialized_len, checksum);
    memcpy(ctx->checksum, checksum, 33);

    /* Generate random IVs */
    if (RAND_bytes(ctx->content_iv, IV_LENGTH) != 1 ||
        RAND_bytes(ctx->key_iv, IV_LENGTH) != 1)
    {
        print_error("Failed to generate random IVs");
        return NULL;
    }

    /* Initialize context */
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx)
    {
        print_error("Failed to create cipher context");
        return NULL;
    }

    /* Get filename base for key derivation */
    char *bname = basename((char *)filename);

    /* Derive file-specific key from master key */
    ctx->file_key = generate_file_key(ctx->master_key, bname, MAX_KEY_ITERATIONS);
    if (!ctx->file_key)
    {
        print_error("Failed to generate file key");
        EVP_CIPHER_CTX_free(cipher_ctx);
        return NULL;
    }

    /* Select AES-256-CBC cipher */
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();

    /* Prepare data for encryption:
     * Structure: [checksum(32)][serialized_opcodes]
     */
    size_t data_len = 32 + serialized_len;
    char *data = (char *)malloc(data_len);

    /* Copy checksum and serialized data */
    memcpy(data, checksum, 32);
    memcpy(data + 32, serialized, serialized_len);

    /* Allocate memory for encrypted data */
    encrypted = (char *)malloc(data_len + EVP_MAX_BLOCK_LENGTH);

    /* Initialize encryption */
    if (EVP_EncryptInit_ex(cipher_ctx, cipher, NULL,
                           (const unsigned char *)ctx->file_key, ctx->content_iv) != 1)
    {
        print_error("Failed to initialize encryption");
        free(data);
        free(encrypted);
        free(ctx->file_key);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return NULL;
    }

    /* Encrypt the data */
    if (EVP_EncryptUpdate(cipher_ctx, (unsigned char *)encrypted, &outlen,
                          (const unsigned char *)data, data_len) != 1)
    {
        print_error("Failed to encrypt data");
        free(data);
        free(encrypted);
        free(ctx->file_key);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return NULL;
    }

    /* Finalize encryption */
    if (EVP_EncryptFinal_ex(cipher_ctx, (unsigned char *)encrypted + outlen, &tmplen) != 1)
    {
        print_error("Failed to finalize encryption");
        free(data);
        free(encrypted);
        free(ctx->file_key);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return NULL;
    }

    /* Set total encrypted length */
    *encrypted_len = outlen + tmplen;

    /* Clean up */
    free(data);
    EVP_CIPHER_CTX_free(cipher_ctx);

    print_debug("Successfully encrypted opcodes: %zu bytes", *encrypted_len);

    return encrypted;
}

/* Function to prepare the final encoded file with PHP stub */
char *prepare_encoded_file(const char *encrypted_data, size_t encrypted_len, size_t *output_len)
{
    const char *stub = "<?php\n"
                       "if(!extension_loaded('zypher')){die('The file '.__FILE__.' is corrupted.\\n\\nScript error: the '.((php_sapi_name()=='cli') ?'Zypher':'<a href=\"https://www.zypher.com\">Zypher</a>').' Loader for PHP needs to be installed.\\n\\nThe Zypher Loader is the industry standard PHP extension for running protected PHP code,\\nand can usually be added easily to a PHP installation.\\n\\nFor Loaders please visit'.((php_sapi_name()=='cli')?\":\\n\\nhttps://get-loader.zypher.com\\n\\nFor\":' <a href=\"https://get-loader.zypher.com\">get-loader.zypher.com</a> and for').' an instructional video please see'.((php_sapi_name()=='cli')?\":\\n\\nhttp://zypher.be/LV\\n\\n\":' <a href=\"http://zypher.be/LV\">http://zypher.be/LV</a> ').'');};exit(0);\n?>\n";

    /* Create base64-encoded version of encrypted data */
    size_t b64_len;
    char *b64_data = (char *)php_base64_encode((const unsigned char *)encrypted_data, encrypted_len, &b64_len);

    /* Calculate the full output size */
    size_t stub_len = strlen(stub);
    size_t sig_len = strlen(ZYPHER_SIGNATURE);
    *output_len = stub_len + sig_len + b64_len;

    /* Allocate memory for output */
    char *output = (char *)malloc(*output_len + 1);

    /* Copy stub and encoded data */
    strcpy(output, stub);
    strcat(output, ZYPHER_SIGNATURE);
    strcat(output, b64_data);

    /* Clean up */
    efree(b64_data);

    print_debug("Prepared encoded file: %zu bytes", *output_len);

    return output;
}

/* Main encoding function */
int encode_php_file(zypher_encoder_options *options)
{
    char *source = NULL;
    size_t source_len = 0;
    zval *opcodes = NULL;
    char *serialized = NULL;
    size_t serialized_len = 0;
    char *encrypted = NULL;
    size_t encrypted_len = 0;
    char *file_content = NULL;
    size_t file_content_len = 0;
    zypher_encoding_context ctx = {0};
    int result = 0;

    printf("Encoding: %s\n", options->input_file);

    /* Set master key */
    ctx.master_key = ZYPHER_MASTER_KEY;

    /* Set encoding timestamp */
    ctx.timestamp = (uint32_t)time(NULL);

    /* Set encoding flags */
    ctx.flags = 0;
    if (options->obfuscate)
        ctx.flags |= ZYPHER_FLAG_OBFUSCATED;
    if (options->expire_timestamp > 0)
        ctx.flags |= ZYPHER_FLAG_EXPIRE;
    if (options->domain_lock)
        ctx.flags |= ZYPHER_FLAG_DOMAIN_LOCK;
    if (!options->allow_debugging)
        ctx.flags |= ZYPHER_FLAG_DEBUG_PROT;

    /* Read source file */
    source = read_file(options->input_file, &source_len);
    if (!source)
    {
        goto cleanup;
    }

    print_debug("Read %zu bytes from %s", source_len, options->input_file);

    /* Compile PHP to opcodes */
    opcodes = compile_php_to_opcodes(source, source_len, options->input_file);
    if (!opcodes)
    {
        goto cleanup;
    }

    /* Serialize opcodes */
    serialized = serialize_opcodes(opcodes, &serialized_len);
    if (!serialized)
    {
        goto cleanup;
    }

    /* Encrypt serialized opcodes */
    encrypted = encrypt_opcodes(serialized, serialized_len, &ctx, options->input_file, &encrypted_len);
    if (!encrypted)
    {
        goto cleanup;
    }

    /* Prepare file header and format */
    unsigned char header[1024];
    int pos = 0;

    /* Format version and type */
    header[pos++] = ZYPHER_FORMAT_VERSION;
    header[pos++] = ZYPHER_FORMAT_OPCODE;

    /* Timestamp (4 bytes) */
    header[pos++] = (ctx.timestamp >> 24) & 0xFF;
    header[pos++] = (ctx.timestamp >> 16) & 0xFF;
    header[pos++] = (ctx.timestamp >> 8) & 0xFF;
    header[pos++] = ctx.timestamp & 0xFF;

    /* Content IV (16 bytes) */
    memcpy(header + pos, ctx.content_iv, IV_LENGTH);
    pos += IV_LENGTH;

    /* Key IV (16 bytes) */
    memcpy(header + pos, ctx.key_iv, IV_LENGTH);
    pos += IV_LENGTH;

    /* Encrypted key length (4 bytes) */
    uint32_t key_len = strlen(ctx.file_key);
    header[pos++] = (key_len >> 24) & 0xFF;
    header[pos++] = (key_len >> 16) & 0xFF;
    header[pos++] = (key_len >> 8) & 0xFF;
    header[pos++] = key_len & 0xFF;

    /* File key (key_len bytes) */
    memcpy(header + pos, ctx.file_key, key_len);
    pos += key_len;

    /* Original filename */
    char *bname = basename(options->input_file);
    uint8_t filename_len = strlen(bname);
    header[pos++] = filename_len;
    memcpy(header + pos, bname, filename_len);
    pos += filename_len;

    /* Create the full encoded content (header + encrypted opcodes) */
    size_t total_len = pos + encrypted_len;
    char *final_data = (char *)malloc(total_len);

    /* Copy header and encrypted data */
    memcpy(final_data, header, pos);
    memcpy(final_data + pos, encrypted, encrypted_len);

    /* Byte rotation for extra obfuscation */
    for (size_t i = 0; i < total_len; i++)
    {
        final_data[i] = (final_data[i] + BYTE_ROTATION_OFFSET) & 0xFF;
    }

    /* Prepare final PHP file with stub */
    file_content = prepare_encoded_file(final_data, total_len, &file_content_len);
    if (!file_content)
    {
        print_error("Failed to prepare encoded file");
        free(final_data);
        goto cleanup;
    }

    /* Write to output file */
    if (!write_file(options->output_file, file_content, file_content_len))
    {
        print_error("Failed to write output file: %s", options->output_file);
        free(final_data);
        free(file_content);
        goto cleanup;
    }

    /* Success */
    printf("Successfully encoded to: %s (%zu bytes)\n", options->output_file, file_content_len);
    result = 1;

    /* Clean up final buffers */
    free(final_data);
    free(file_content);

cleanup:
    /* Clean up resources */
    if (source)
        free(source);
    if (serialized)
        efree(serialized);
    if (encrypted)
        free(encrypted);
    if (ctx.file_key)
        free(ctx.file_key);
    if (opcodes)
    {
        zval_ptr_dtor(opcodes);
        free(opcodes);
    }

    return result;
}