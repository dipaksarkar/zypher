/*
  +----------------------------------------------------------------------+
  | Zypher PHP Loader                                                    |
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/base64.h"
#include "ext/standard/md5.h"
#include "ext/standard/php_var.h"

#include "php_zypher.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>

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
        php_printf("DEBUG: Format type: %d (opcode)\n", metadata->format_type);
    }

    /* Verify format version */
    if (metadata->format_version != ZYPHER_FORMAT_VERSION)
    {
        if (DEBUG)
            php_printf("DEBUG: Unsupported format version %d\n", metadata->format_version);
        zend_string_release(decoded_str);
        return ZYPHER_ERR_INVALID_FILE;
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

    if (DEBUG)
    {
        php_printf("DEBUG: Timestamp: %u\n", metadata->timestamp);
    }

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

/* Decrypt and deserialize PHP code from encoded data */
int decrypt_php_code(const char *encoded_data, size_t length, char **source_code, char **filename)
{
    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;
    char *serialized_data = NULL;
    size_t serialized_len = 0;
    char md5_hash[33] = {0};
    char computed_md5[33] = {0};
    int ret = 0;

    /* Extract the IV from the encoded data */
    if (length < IV_LENGTH + 16)
    { /* IV + minimum ciphertext */
        return 0;
    }

    unsigned char iv[IV_LENGTH];
    memcpy(iv, encoded_data, IV_LENGTH);

    /* Decrypt the data using the decrypt_file_content function instead */
    size_t output_len = 0;
    char *decrypted_content = decrypt_file_content(encoded_data + IV_LENGTH,
                                                   length - IV_LENGTH,
                                                   ZYPHER_MASTER_KEY,
                                                   *filename,
                                                   &output_len,
                                                   NULL);

    if (!decrypted_content)
    {
        return 0;
    }

    decrypted = (unsigned char *)decrypted_content;
    decrypted_len = output_len;

    /* Verify minimum length for MD5 (32 bytes) + serialized data */
    if (decrypted_len <= 32)
    {
        efree(decrypted);
        return 0;
    }

    /* Extract MD5 hash (first 32 bytes) */
    memcpy(md5_hash, decrypted, 32);
    md5_hash[32] = '\0';

    /* Extract serialized data */
    serialized_data = (char *)decrypted + 32;
    serialized_len = decrypted_len - 32;

    /* Calculate MD5 instead of calling compute_md5 */
    EVP_MD_CTX *mdctx;
    unsigned int md_len;
    unsigned char digest[16];

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, (unsigned char *)serialized_data, serialized_len);
    EVP_DigestFinal_ex(mdctx, digest, &md_len);
    EVP_MD_CTX_free(mdctx);

    for (int i = 0; i < 16; i++)
    {
        sprintf(&computed_md5[i * 2], "%02x", digest[i]);
    }
    computed_md5[32] = '\0';

    /* Verify MD5 hash */
    if (strcmp(md5_hash, computed_md5) != 0)
    {
        efree(decrypted);
        return 0;
    }

    /* Unserialize data which contains ['filename' => string, 'contents' => string] */
    zval zv_data;
    ZVAL_NULL(&zv_data);

    /* PHP 8.3 compatible unserialization */
    const unsigned char *p = (const unsigned char *)serialized_data;
    const unsigned char *end = p + serialized_len;

    if (!php_var_unserialize(&zv_data, &p, end, NULL))
    {
        efree(decrypted);
        return 0;
    }

    /* Extract filename and source code from unserialized data */
    if (Z_TYPE(zv_data) == IS_ARRAY)
    {
        zval *z_filename = zend_hash_str_find(Z_ARRVAL(zv_data), "filename", sizeof("filename") - 1);
        zval *z_contents = zend_hash_str_find(Z_ARRVAL(zv_data), "contents", sizeof("contents") - 1);

        if (z_filename && Z_TYPE_P(z_filename) == IS_STRING &&
            z_contents && Z_TYPE_P(z_contents) == IS_STRING)
        {
            *filename = estrndup(Z_STRVAL_P(z_filename), Z_STRLEN_P(z_filename));
            *source_code = estrndup(Z_STRVAL_P(z_contents), Z_STRLEN_P(z_contents));

            ret = 1; /* Success */
        }
    }

    /* Clean up */
    zval_ptr_dtor(&zv_data);
    efree(decrypted);

    return ret;
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
        zend_hash_init(ZYPHER_G(opcode_cache), 64, NULL, ZVAL_PTR_DTOR, 0);
    }

    /* Check if this file has already been cached */
    zend_string *filename_key = zend_string_copy(filename);
    zval *cached_opcodes = zend_hash_find(ZYPHER_G(opcode_cache), filename_key);

    if (cached_opcodes != NULL && Z_TYPE_P(cached_opcodes) == IS_ARRAY)
    {
        if (DEBUG)
            php_printf("DEBUG: Found cached opcodes for %s\n", ZSTR_VAL(filename));

        /* Create op_array from cached opcodes by converting to string first */
        char *decoded_data = estrndup(Z_STRVAL_P(cached_opcodes), Z_STRLEN_P(cached_opcodes));
        zend_op_array *op_array = zypher_load_opcodes(decoded_data, ZSTR_VAL(filename));
        efree(decoded_data);
        zend_string_release(filename_key);
        return op_array;
    }

    /* Try to unserialize the opcode data */
    const unsigned char *p = (const unsigned char *)opcode_data;
    const unsigned char *end = p + data_len;

    if (!php_var_unserialize(&opcodes, &p, end, NULL))
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to unserialize opcode data\n");
        zend_string_release(filename_key);
        return NULL;
    }

    if (Z_TYPE(opcodes) != IS_ARRAY)
    {
        if (DEBUG)
            php_printf("DEBUG: Unserialized data is not an array\n");
        zval_ptr_dtor(&opcodes);
        zend_string_release(filename_key);
        return NULL;
    }

    /* Create op_array from opcodes - with error handling */
    zend_op_array *op_array = NULL;

    /* Use try/catch equivalent with zend_try/zend_catch to prevent segfaults */
    zend_try
    {
        /* Convert zval to string for zypher_load_opcodes */
        char *decoded_data = estrndup(Z_STRVAL_P(&opcodes), Z_STRLEN_P(&opcodes));
        op_array = zypher_load_opcodes(decoded_data, ZSTR_VAL(filename));
        efree(decoded_data);
    }
    zend_catch
    {
        if (DEBUG)
            php_printf("DEBUG: Exception caught while loading opcodes\n");
        op_array = NULL;
    }
    zend_end_try();

    /* Only cache if successful */
    if (op_array)
    {
        if (DEBUG)
            php_printf("DEBUG: Caching successful opcodes for %s\n", ZSTR_VAL(filename));

        /* Add to cache with proper reference counting */
        zval cached_zval;
        ZVAL_COPY(&cached_zval, &opcodes);
        zend_hash_update(ZYPHER_G(opcode_cache), filename_key, &cached_zval);
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

/* Function to decrypt and execute encoded PHP content */
zend_op_array *decrypt_and_execute(const char *encrypted_data, size_t data_size, const char *filename)
{
    unsigned char *decrypted = NULL;
    size_t decrypted_size = 0;
    zend_op_array *op_array = NULL;
    char *checksum_part, *serialized_part;
    char calculated_checksum[33];
    size_t checksum_len = 32; /* MD5 hex digest length */
    zval data_zval;
    HashTable *data_array;
    zval *source_zval, *filename_zval;

    /* Decrypt the encoded content using decrypt_file_content instead of decrypt_content */
    size_t output_len = 0;
    zypher_file_metadata metadata = {0};

    char *decrypted_content = decrypt_file_content(encrypted_data, data_size,
                                                   ZYPHER_MASTER_KEY, filename,
                                                   &output_len, &metadata);

    if (!decrypted_content)
    {
        return NULL;
    }

    decrypted = (unsigned char *)decrypted_content;
    decrypted_size = output_len;

    /* Verify there's enough data for checksum + serialized data */
    if (decrypted_size <= checksum_len)
    {
        efree(decrypted);
        return NULL;
    }

    /* Split into checksum and serialized data */
    checksum_part = (char *)decrypted;
    serialized_part = checksum_part + checksum_len;
    size_t serialized_len = decrypted_size - checksum_len;

    /* Calculate checksum of serialized data using EVP APIs */
    unsigned char digest[16];
    unsigned int md_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, (unsigned char *)serialized_part, serialized_len);
    EVP_DigestFinal_ex(mdctx, digest, &md_len);
    EVP_MD_CTX_free(mdctx);

    /* Convert binary digest to hex string */
    for (int i = 0; i < 16; i++)
    {
        sprintf(calculated_checksum + (i * 2), "%02x", digest[i]);
    }
    calculated_checksum[32] = '\0';

    /* Compare checksums */
    if (strncmp(checksum_part, calculated_checksum, checksum_len) != 0)
    {
        zend_error(E_WARNING, "Zypher: Checksum verification failed for %s", filename);
        efree(decrypted);
        return NULL;
    }

    /* Unserialize the data - using PHP 8.3 compatible code */
    ZVAL_NULL(&data_zval);

    const unsigned char *p = (const unsigned char *)serialized_part;
    const unsigned char *end = p + serialized_len;

    if (!php_var_unserialize(&data_zval, &p, end, NULL))
    {
        zend_error(E_WARNING, "Zypher: Failed to unserialize data");
        efree(decrypted);
        return NULL;
    }

    /* Extract the data from the unserialized array */
    if (Z_TYPE(data_zval) != IS_ARRAY)
    {
        zend_error(E_WARNING, "Zypher: Invalid data format");
        zval_ptr_dtor(&data_zval);
        efree(decrypted);
        return NULL;
    }

    data_array = Z_ARRVAL(data_zval);

    /* Get source code from array */
    if ((source_zval = zend_hash_str_find(data_array, "contents", sizeof("contents") - 1)) == NULL ||
        Z_TYPE_P(source_zval) != IS_STRING)
    {
        zend_error(E_WARNING, "Zypher: Missing or invalid source code in encoded file");
        zval_ptr_dtor(&data_zval);
        efree(decrypted);
        return NULL;
    }

    /* Get original filename from array */
    if ((filename_zval = zend_hash_str_find(data_array, "filename", sizeof("filename") - 1)) != NULL &&
        Z_TYPE_P(filename_zval) == IS_STRING)
    {
        /* Use original filename for error messages */
        filename = Z_STRVAL_P(filename_zval);
    }

    /* Evaluate the PHP code using PHP 8.3 compatible API */
    zend_string *filename_str = zend_string_init(filename, strlen(filename), 0);
    op_array = zend_compile_string(Z_STR_P(source_zval), filename_str, ZEND_COMPILE_POSITION_AT_OPEN_TAG);
    zend_string_release(filename_str);

    /* Clean up */
    zval_ptr_dtor(&data_zval);
    efree(decrypted);

    return op_array;
}