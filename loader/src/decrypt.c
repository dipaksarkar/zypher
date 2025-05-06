#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/base64.h"
#include "ext/standard/md5.h"
#include "ext/standard/php_var.h"
#include "Zend/zend_compile.h"
#include "Zend/zend_execute.h"
#include "Zend/zend_vm.h"
#include "Zend/zend_operators.h"

#include "src/php_loader.h"
#include "decrypt.h"
#include "security.h"
#include "utils.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>

/* Include the external declaration for zypher_globals */
#ifndef ZTS
extern zend_zypher_globals zypher_globals;
#endif

/* Utility function to read file contents */
char *read_file_contents(const char *filename, size_t *size)
{
    php_stream *stream;
    char *contents;
    size_t file_size;
    php_stream_statbuf stat_buf;

    stream = php_stream_open_wrapper((char *)filename, "rb", REPORT_ERRORS, NULL);
    if (!stream)
    {
        return NULL;
    }

    /* Determine file size using proper stat_buf structure */
    if (php_stream_stat(stream, &stat_buf) != 0)
    {
        php_stream_close(stream);
        return NULL;
    }

    file_size = stat_buf.sb.st_size;

    /* Allocate memory for file contents */
    contents = emalloc(file_size + 1);
    if (!contents)
    {
        php_stream_close(stream);
        return NULL;
    }

    /* Read file contents */
    if (php_stream_read(stream, contents, file_size) != file_size)
    {
        efree(contents);
        php_stream_close(stream);
        return NULL;
    }

    /* Null terminate */
    contents[file_size] = '\0';

    /* Close stream */
    php_stream_close(stream);

    if (size)
    {
        *size = file_size;
    }

    return contents;
}

/* Check if content has been tampered with via checksum */
int verify_content_integrity(const char *content, size_t content_len, const char *checksum)
{
    char calculated_checksum[33];
    PHP_MD5_CTX context;
    unsigned char digest[16];

    // Calculate MD5 of content
    PHP_MD5Init(&context);
    PHP_MD5Update(&context, (unsigned char *)content, content_len);
    PHP_MD5Final(digest, &context);

    // Convert to hex string
    for (int i = 0; i < 16; i++)
    {
        sprintf(calculated_checksum + (i * 2), "%02x", digest[i]);
    }
    calculated_checksum[32] = '\0';

    // Compare
    return strcmp(calculated_checksum, checksum) == 0 ? ZYPHER_ERR_NONE : ZYPHER_ERR_TAMPERED;
}

/* Extract metadata from encoded content */
int extract_file_metadata(const char *encoded_content, size_t encoded_length,
                          zypher_file_metadata *metadata)
{
    zend_string *decoded_str;
    const char *signature_pos;

    /* Find Zypher signature anywhere in the file, not just at the beginning */
    signature_pos = strstr(encoded_content, ZYPHER_SIGNATURE);
    if (!signature_pos || (size_t)(signature_pos - encoded_content) >= encoded_length - SIGNATURE_LENGTH)
    {
        if (DEBUG)
            php_printf("DEBUG: Signature not found in the content\n");
        return ZYPHER_ERR_INVALID_FILE;
    }

    if (DEBUG)
    {
        php_printf("DEBUG: Found signature at offset %zu\n", (size_t)(signature_pos - encoded_content));
    }

    /* Base64 decode the content after signature */
    decoded_str = php_base64_decode(
        (const unsigned char *)signature_pos + SIGNATURE_LENGTH,
        encoded_length - ((size_t)(signature_pos - encoded_content) + SIGNATURE_LENGTH));

    if (!decoded_str)
    {
        if (DEBUG)
            php_printf("DEBUG: Base64 decoding failed\n");
        return ZYPHER_ERR_INVALID_FILE;
    }

    /* Handle byte rotation if present */
    char *rotated_content = NULL;

    /* Check if first byte value suggests byte rotation (+7) */
    if (ZSTR_LEN(decoded_str) > 0)
    {
        /* Assume byte rotation is used and un-rotate bytes */
        rotated_content = emalloc(ZSTR_LEN(decoded_str) + 1);
        for (size_t i = 0; i < ZSTR_LEN(decoded_str); i++)
        {
            rotated_content[i] = (char)((unsigned char)(ZSTR_VAL(decoded_str)[i] - BYTE_ROTATION_OFFSET) & 0xFF);
        }
        rotated_content[ZSTR_LEN(decoded_str)] = '\0';

        /* Replace decoded_str with rotated content for further processing */
        zend_string *old_str = decoded_str;
        decoded_str = zend_string_init(rotated_content, ZSTR_LEN(old_str), 0);
        zend_string_release(old_str);
        efree(rotated_content);
    }

    /* Parse the format - payload starts with 2 bytes for version and format_type */
    size_t pos = 0;
    unsigned char *data = (unsigned char *)ZSTR_VAL(decoded_str);
    size_t data_len = ZSTR_LEN(decoded_str);

    /* Extract format version and type */
    if (data_len < pos + 2)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for version and format type\n");
        zend_string_release(decoded_str);
        return ZYPHER_ERR_INVALID_FILE;
    }

    metadata->format_version = data[pos++];
    metadata->format_type = data[pos++];

    if (DEBUG)
    {
        php_printf("DEBUG: Format version: %d\n", metadata->format_version);
        php_printf("DEBUG: Format type: %d (%s)\n",
                   metadata->format_type,
                   metadata->format_type == ZYPHER_FORMAT_OPCODE ? "opcode" : "source");
    }

    /* Extract timestamp */
    if (data_len < pos + 4)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for timestamp\n");
        zend_string_release(decoded_str);
        return ZYPHER_ERR_INVALID_FILE;
    }

    metadata->timestamp = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
    pos += 4;

    /* Extract IVs */
    if (data_len < pos + IV_LENGTH * 2)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for IVs\n");
        zend_string_release(decoded_str);
        return ZYPHER_ERR_INVALID_FILE;
    }

    memcpy(metadata->content_iv, data + pos, IV_LENGTH);
    pos += IV_LENGTH;
    memcpy(metadata->key_iv, data + pos, IV_LENGTH);
    pos += IV_LENGTH;

    /* Extract key length and encrypted key */
    if (data_len < pos + 4)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for key length\n");
        zend_string_release(decoded_str);
        return ZYPHER_ERR_INVALID_FILE;
    }

    uint32_t key_length = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
    pos += 4;

    if (data_len < pos + key_length)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for encrypted key\n");
        zend_string_release(decoded_str);
        return ZYPHER_ERR_INVALID_FILE;
    }

    char *encrypted_key = emalloc(key_length + 1);
    memcpy(encrypted_key, data + pos, key_length);
    encrypted_key[key_length] = '\0';
    pos += key_length;

    /* Extract filename length and filename */
    if (data_len < pos + 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for filename length\n");
        efree(encrypted_key);
        zend_string_release(decoded_str);
        return ZYPHER_ERR_INVALID_FILE;
    }

    uint8_t filename_length = data[pos++];

    if (data_len < pos + filename_length)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for filename\n");
        efree(encrypted_key);
        zend_string_release(decoded_str);
        return ZYPHER_ERR_INVALID_FILE;
    }

    metadata->orig_filename = emalloc(filename_length + 1);
    memcpy(metadata->orig_filename, data + pos, filename_length);
    metadata->orig_filename[filename_length] = '\0';
    pos += filename_length;

    /* Store encrypted key for later decryption */
    metadata->file_key = encrypted_key;

    /* Cleanup */
    zend_string_release(decoded_str);
    return ZYPHER_ERR_NONE;
}

/* Enhanced decrypt function that handles both source code and opcodes */
char *decrypt_file_content(const char *encoded_content, size_t encoded_length,
                           const char *master_key, const char *filename,
                           size_t *out_length, zypher_file_metadata *metadata)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    int outlen, tmplen;
    zend_string *decoded_str;
    size_t pos = 0;
    const char *signature_pos;
    unsigned long openssl_err = 0;

    /* Debug output */
    if (DEBUG)
    {
        php_printf("DEBUG: Decrypting content of length %zu\n", encoded_length);
        php_printf("DEBUG: Using master key: '%s'\n", master_key);
        php_printf("DEBUG: Using filename for decryption: '%s'\n", filename);
    }

    /* Find Zypher signature anywhere in the file, not just at the beginning */
    signature_pos = strstr(encoded_content, ZYPHER_SIGNATURE);
    if (!signature_pos || (size_t)(signature_pos - encoded_content) >= encoded_length - SIGNATURE_LENGTH)
    {
        if (DEBUG)
            php_printf("DEBUG: Signature not found in the content\n");
        return NULL;
    }

    /* Base64 decode the content after signature */
    decoded_str = php_base64_decode(
        (const unsigned char *)signature_pos + SIGNATURE_LENGTH,
        encoded_length - ((size_t)(signature_pos - encoded_content) + SIGNATURE_LENGTH));

    if (!decoded_str)
    {
        if (DEBUG)
            php_printf("DEBUG: Base64 decoding failed\n");
        return NULL;
    }

    /* Handle byte rotation - un-rotate bytes */
    char *rotated_content = NULL;
    rotated_content = emalloc(ZSTR_LEN(decoded_str) + 1);

    for (size_t i = 0; i < ZSTR_LEN(decoded_str); i++)
    {
        rotated_content[i] = (char)((unsigned char)(ZSTR_VAL(decoded_str)[i] - BYTE_ROTATION_OFFSET) & 0xFF);
    }
    rotated_content[ZSTR_LEN(decoded_str)] = '\0';

    /* Replace decoded_str with rotated content */
    zend_string *old_str = decoded_str;
    decoded_str = zend_string_init(rotated_content, ZSTR_LEN(old_str), 0);
    zend_string_release(old_str);
    efree(rotated_content);

    /* Parse the format - new format with version and format_type */
    pos = 0;
    unsigned char *data = (unsigned char *)ZSTR_VAL(decoded_str);
    size_t data_len = ZSTR_LEN(decoded_str);

    /* Extract format version */
    if (data_len < pos + 2)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for version and format type bytes\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract format version and type */
    metadata->format_version = data[pos++];
    metadata->format_type = data[pos++];

    if (DEBUG)
    {
        php_printf("DEBUG: Format version: %d\n", metadata->format_version);
        php_printf("DEBUG: Format type: %d (%s)\n",
                   metadata->format_type,
                   metadata->format_type == ZYPHER_FORMAT_OPCODE ? "opcode" : "source");
    }

    /* Verify format version */
    if (metadata->format_version != ZYPHER_FORMAT_VERSION_V1 &&
        metadata->format_version != ZYPHER_FORMAT_VERSION_V2)
    {
        if (DEBUG)
            php_printf("DEBUG: Unsupported format version %d\n", metadata->format_version);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract timestamp */
    if (data_len < pos + 4)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for timestamp\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    metadata->timestamp = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
    pos += 4;

    if (DEBUG)
    {
        php_printf("DEBUG: Timestamp: %u\n", metadata->timestamp);
    }

    /* Verify license based on timestamp */
    int license_error = zypher_verify_license(NULL, metadata->timestamp);
    if (license_error != ZYPHER_ERR_NONE)
    {
        if (DEBUG)
        {
            switch (license_error)
            {
            case ZYPHER_ERR_EXPIRED:
                php_printf("DEBUG: License expired\n");
                break;
            case ZYPHER_ERR_DOMAIN:
                php_printf("DEBUG: Domain mismatch\n");
                break;
            default:
                php_printf("DEBUG: License error %d\n", license_error);
                break;
            }
        }
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract content IV */
    if (data_len < pos + IV_LENGTH)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for content IV\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    memcpy(metadata->content_iv, data + pos, IV_LENGTH);
    pos += IV_LENGTH;

    /* Extract key IV */
    if (data_len < pos + IV_LENGTH)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for key IV\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    memcpy(metadata->key_iv, data + pos, IV_LENGTH);
    pos += IV_LENGTH;

    /* Extract key length */
    if (data_len < pos + 4)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for key length\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    uint32_t key_length = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
    pos += 4;

    if (DEBUG)
    {
        php_printf("DEBUG: Key length: %u\n", key_length);
    }

    /* Extract encrypted file key */
    if (data_len < pos + key_length)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for encrypted file key\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    char *encrypted_file_key = emalloc(key_length + 1);
    memcpy(encrypted_file_key, data + pos, key_length);
    encrypted_file_key[key_length] = '\0';
    pos += key_length;

    /* Extract original filename length */
    if (data_len < pos + 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for filename length\n");
        efree(encrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    uint8_t filename_length = data[pos++];

    /* Extract original filename - important for key derivation */
    if (data_len < pos + filename_length)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for original filename\n");
        efree(encrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    metadata->orig_filename = emalloc(filename_length + 1);
    memcpy(metadata->orig_filename, data + pos, filename_length);
    metadata->orig_filename[filename_length] = '\0';
    pos += filename_length;

    if (DEBUG)
    {
        php_printf("DEBUG: Original filename: %s\n", metadata->orig_filename);
    }

    /* The rest is encrypted content */
    size_t encrypted_content_length = data_len - pos;
    if (encrypted_content_length == 0)
    {
        if (DEBUG)
            php_printf("DEBUG: No encrypted content\n");
        efree(encrypted_file_key);
        efree(metadata->orig_filename);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Derive master key from original filename */
    char derived_key[65];

    /* Use original filename for key derivation, not the current one */
    zypher_derive_key(master_key, metadata->orig_filename, derived_key, 1000);

    if (DEBUG)
    {
        php_printf("DEBUG: Derived master key: %s\n", derived_key);
    }

    /* Create OpenSSL cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to create cipher context\n");
        efree(encrypted_file_key);
        efree(metadata->orig_filename);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Select AES-256-CBC cipher */
    cipher = EVP_aes_256_cbc();

    /* Decrypt the file key with derived master key */
    char *decrypted_file_key = emalloc(key_length + EVP_MAX_BLOCK_LENGTH);

    /* Initialize decryption process */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL,
                           (unsigned char *)derived_key, metadata->key_iv) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(metadata->orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Perform decryption */
    if (EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_file_key, &outlen,
                          (unsigned char *)encrypted_file_key, key_length) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to decrypt file key\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(metadata->orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Finalize decryption */
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted_file_key + outlen, &tmplen) != 1)
    {
        openssl_err = ERR_get_error();
        char err_msg[256] = {0};
        ERR_error_string_n(openssl_err, err_msg, sizeof(err_msg));

        if (DEBUG)
        {
            php_printf("DEBUG: Failed to finalize key decryption: %s (error code: 0x%lx)\n",
                       err_msg, openssl_err);
        }
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(metadata->orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    outlen += tmplen;
    decrypted_file_key[outlen] = '\0';

    /* Store decrypted file key in metadata for later use */
    metadata->file_key = estrndup(decrypted_file_key, outlen);

    if (DEBUG)
    {
        php_printf("DEBUG: Decrypted file key: %s (length: %d)\n", decrypted_file_key, outlen);
    }

    /* Now decrypt actual file content using the decrypted file key */
    EVP_CIPHER_CTX_reset(ctx);

    /* Initialize encryption with file key and content IV */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL,
                           (unsigned char *)decrypted_file_key, metadata->content_iv) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to initialize content decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(metadata->file_key);
        efree(metadata->orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Allocate memory for decrypted content */
    char *decrypted = emalloc(encrypted_content_length + EVP_MAX_BLOCK_LENGTH + 1);

    /* Perform decryption */
    if (EVP_DecryptUpdate(ctx, (unsigned char *)decrypted, &outlen,
                          (unsigned char *)(data + pos), encrypted_content_length) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to decrypt content\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(metadata->file_key);
        efree(metadata->orig_filename);
        efree(decrypted_file_key);
        efree(decrypted);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Finalize decryption */
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted + outlen, &tmplen) != 1)
    {
        openssl_err = ERR_get_error();
        if (DEBUG)
        {
            php_printf("DEBUG: Failed to finalize content decryption: %s (error code: %lu)\n",
                       ERR_error_string(openssl_err, NULL), openssl_err);
        }
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(metadata->file_key);
        efree(metadata->orig_filename);
        efree(decrypted_file_key);
        efree(decrypted);
        zend_string_release(decoded_str);
        return NULL;
    }

    outlen += tmplen;
    decrypted[outlen] = '\0';

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    efree(encrypted_file_key);
    efree(decrypted_file_key);

    /* Extract checksum from the beginning of decrypted data */
    memcpy(metadata->checksum, decrypted, 32);
    metadata->checksum[32] = '\0';

    /* Move the actual content to the beginning */
    memmove(decrypted, decrypted + 32, outlen - 32 + 1);
    outlen -= 32;

    if (DEBUG)
    {
        php_printf("DEBUG: Extracted checksum: %s\n", metadata->checksum);
    }

    /* Verify content integrity with checksum */
    if (verify_content_integrity(decrypted, outlen, metadata->checksum) != ZYPHER_ERR_NONE)
    {
        if (DEBUG)
            php_printf("DEBUG: Content integrity check failed\n");
        efree(metadata->file_key);
        efree(metadata->orig_filename);
        efree(decrypted);
        zend_string_release(decoded_str);
        return NULL;
    }

    if (DEBUG)
    {
        php_printf("DEBUG: Content integrity verified!\n");
    }

    /* Set output length */
    if (out_length)
        *out_length = outlen;

    zend_string_release(decoded_str);
    return decrypted;
}

/* Process and load opcodes from serialized data */
zend_op_array *process_opcodes(char *opcode_data, size_t data_len, zend_string *filename)
{
    if (!opcode_data || data_len == 0)
    {
        if (DEBUG)
            php_printf("DEBUG: No opcode data to process\n");
        return NULL;
    }

    if (DEBUG)
    {
        php_printf("DEBUG: Processing opcodes for %s (data length: %zu)\n",
                   ZSTR_VAL(filename), data_len);
    }

    /* Initialize a zval to hold the unserialized opcodes */
    zval opcodes;
    ZVAL_NULL(&opcodes);

    /* Check if the opcode cache is initialized */
    if (!ZYPHER_G(opcode_cache))
    {
        ALLOC_HASHTABLE(ZYPHER_G(opcode_cache));
        zend_hash_init(ZYPHER_G(opcode_cache), 64, NULL, ZVAL_PTR_DTOR, 0); /* Add proper destructor */
    }

    /* Check if this file has already been cached */
    zend_string *filename_key = zend_string_copy(filename);
    zval *cached_opcodes = zend_hash_find(ZYPHER_G(opcode_cache), filename_key);

    if (cached_opcodes != NULL)
    {
        if (DEBUG)
            php_printf("DEBUG: Found cached opcodes for %s\n", ZSTR_VAL(filename));

        /* Create op_array from cached opcodes */
        zend_op_array *op_array = zypher_load_opcodes(cached_opcodes, filename);
        zend_string_release(filename_key);
        return op_array;
    }

    /* Try to unserialize the opcode data - using PHP 8.3 compatible approach */
    php_unserialize_data_t var_hash;
    PHP_VAR_UNSERIALIZE_INIT(var_hash);

    const unsigned char *p = (const unsigned char *)opcode_data;
    const unsigned char *end = p + data_len;

    if (!php_var_unserialize(&opcodes, &p, end, &var_hash))
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to unserialize opcode data\n");
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
        zend_string_release(filename_key);
        return NULL;
    }

    PHP_VAR_UNSERIALIZE_DESTROY(var_hash);

    if (Z_TYPE(opcodes) != IS_ARRAY)
    {
        if (DEBUG)
            php_printf("DEBUG: Unserialized data is not an array\n");
        zval_ptr_dtor(&opcodes);
        zend_string_release(filename_key);
        return NULL;
    }

    /* Create op_array from opcodes */
    zend_op_array *op_array = zypher_load_opcodes(&opcodes, filename);

    if (op_array)
    {
        /* Only cache if successful */
        zval cached_zval;
        ZVAL_COPY(&cached_zval, &opcodes);
        zend_hash_add(ZYPHER_G(opcode_cache), filename_key, &cached_zval);
    }

    /* Clean up */
    zval_ptr_dtor(&opcodes);
    zend_string_release(filename_key);

    return op_array;
}

/* Free the opcode cache */
void zypher_free_opcode_cache(void)
{
    if (ZYPHER_G(opcode_cache))
    {
        zend_hash_destroy(ZYPHER_G(opcode_cache));
        FREE_HASHTABLE(ZYPHER_G(opcode_cache));
        ZYPHER_G(opcode_cache) = NULL;
    }
}