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
#include "Zend/zend_compile.h"
#include "ext/standard/md5.h"
#include "ext/standard/base64.h"
#include "ext/standard/php_var.h"
#include "php_zypher.h"
#include "../include/zypher_loader.h"
#include "../include/zypher_common.h"
#include "include/zypher_utils.h"
#include <openssl/evp.h>
#include <libgen.h>

/* Custom zend_compile_file function to handle encoded files */
zend_op_array *zypher_compile_file(zend_file_handle *file_handle, int type)
{
    char *buffer = NULL;
    size_t buffer_len = 0;
    char *decoded = NULL;
    size_t decoded_len = 0;
    char signature[SIGNATURE_LENGTH + 1] = {0};
    int is_encoded = 0;
    zend_op_array *op_array = NULL;
    const char *filename;
    zypher_file_metadata metadata = {0};

    /* Skip if no file or already processed */
    if (!file_handle || !file_handle->filename)
    {
        if (DEBUG)
            php_printf("DEBUG: No filename provided to zypher_compile_file\n");
        return original_compile_file(file_handle, type);
    }

    /* Handle zend_string filename in PHP 8.x */
    filename = ZSTR_VAL(file_handle->filename);

    if (DEBUG)
        php_printf("DEBUG: Checking file: %s\n", filename);

    /* Read the file contents */
    buffer = read_file_contents(filename, &buffer_len);
    if (!buffer || buffer_len < SIGNATURE_LENGTH)
    {
        /* Not our file or couldn't read it */
        if (buffer)
        {
            efree(buffer);
        }
        if (DEBUG)
            php_printf("DEBUG: File too small or couldn't be read\n");
        return original_compile_file(file_handle, type);
    }

    /* Check for direct signature at start of file */
    memcpy(signature, buffer, SIGNATURE_LENGTH);
    signature[SIGNATURE_LENGTH] = '\0';

    if (DEBUG)
    {
        php_printf("DEBUG: File signature check: %.10s... (expected: %s)\n", buffer, ZYPHER_SIGNATURE);
    }

    /* Check if the file is encoded by looking for the signature anywhere in the first few KB */
    if (strcmp(signature, ZYPHER_SIGNATURE) == 0)
    {
        is_encoded = 1;
        if (DEBUG)
            php_printf("DEBUG: File is directly encoded with Zypher\n");
    }
    else
    {
        /* Look for signature within the first 1KB in case it follows PHP comments or whitespace */
        size_t search_len = buffer_len > 1024 ? 1024 : buffer_len;
        for (size_t i = 0; i <= search_len - SIGNATURE_LENGTH; i++)
        {
            if (memcmp(buffer + i, ZYPHER_SIGNATURE, SIGNATURE_LENGTH) == 0)
            {
                is_encoded = 1;
                if (DEBUG)
                {
                    php_printf("DEBUG: Found Zypher signature at offset %zu\n", i);
                }
                break;
            }
        }
    }

    if (is_encoded)
    {
        /* Get the filename we should use for key derivation - just the base name like the encoder does */
        char *filename_dup = estrndup(filename, strlen(filename));
        char *base_name = basename(filename_dup);

        if (DEBUG)
            php_printf("DEBUG: Using base filename '%s' for decryption\n", base_name);

        /* Structure to hold metadata */
        memset(&metadata, 0, sizeof(metadata));

        /* Extract metadata first to determine format type */
        if (extract_file_metadata(buffer, buffer_len, &metadata) != ZYPHER_ERROR_NONE)
        {
            if (DEBUG)
                php_printf("DEBUG: Failed to extract metadata\n");
            efree(buffer);
            efree(filename_dup);
            return NULL;
        }

        /* Decrypt content using enhanced decryption */
        decoded = decrypt_file_content(buffer,
                                       buffer_len,
                                       ZYPHER_MASTER_KEY, base_name, &decoded_len,
                                       &metadata);

        /* Free memory for buffer */
        efree(buffer);
        efree(filename_dup);

        if (!decoded)
        {
            php_error_docref(NULL, E_WARNING, "Failed to decrypt encoded file: %s", filename);
            if (DEBUG)
                php_printf("DEBUG: Decryption failed\n");
            return NULL;
        }

        if (DEBUG)
            php_printf("DEBUG: Successfully decrypted %zu bytes of content\n", decoded_len);

        /* Process opcodes from decoded content */
        if (DEBUG)
            php_printf("DEBUG: Processing opcodes from decoded content\n");

        /* Process the decoded opcodes */
        op_array = zypher_load_opcodes(decoded, filename);

        /* Clean up */
        efree(decoded);

        if (!op_array)
        {
            if (DEBUG)
                php_printf("DEBUG: Failed to process opcodes, compilation failed\n");
            php_error_docref(NULL, E_WARNING, "Failed to process opcodes for: %s", filename);
            return NULL;
        }

        if (DEBUG)
            php_printf("DEBUG: Successfully loaded opcodes for %s\n", filename);

        return op_array;
    }

    if (DEBUG)
    {
        php_printf("DEBUG: Not an encoded file, passing to original handler\n");
    }

    /* Not our file, let original handler process it */
    efree(buffer);
    return original_compile_file(file_handle, type);
}

/* Load opcodes from decoded data */
zend_op_array *zypher_load_opcodes(const char *decoded_data, const char *filename)
{
    zend_op_array *op_array = NULL;
    char *source_code = NULL;
    char *source_hint = NULL;
    char *namespace = NULL;
    char *classname = NULL;
    zval data_zval;

    /* Extract the MD5 hash (first 32 bytes) and the base64-encoded serialized data */
    const char *md5_hash = decoded_data;
    const char *base64_data = decoded_data + 32;

    /* Calculate MD5 of the base64 data for verification */
    char calculated_md5[33];
    unsigned char digest[16];

    /* Use EVP for MD5 calculation instead of PHP_MD5 functions */
    EVP_MD_CTX *mdctx;
    unsigned int md_len;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, (unsigned char *)base64_data, strlen(base64_data));
    EVP_DigestFinal_ex(mdctx, digest, &md_len);
    EVP_MD_CTX_free(mdctx);

    for (int i = 0; i < 16; i++)
    {
        sprintf(&calculated_md5[i * 2], "%02x", digest[i]);
    }
    calculated_md5[32] = '\0';

    /* Verify MD5 hash */
    if (strncmp(md5_hash, calculated_md5, 32) != 0)
    {
        php_error_docref(NULL, E_WARNING, "Zypher: Checksum verification failed for %s", filename);
        return NULL;
    }

    /* Decode base64 using our own utility function */
    size_t decoded_len;
    unsigned char *serialized_data = base64_decode(base64_data, strlen(base64_data), &decoded_len);

    if (!serialized_data || decoded_len == 0)
    {
        php_error_docref(NULL, E_WARNING, "Zypher: Failed to decode base64 data for %s", filename);
        return NULL;
    }

    /* Unserialize the PHP array data */
    ZVAL_NULL(&data_zval);

    /* PHP 8.x compatible unserialization - direct use of php_var_unserialize */
    const unsigned char *p = serialized_data;
    const unsigned char *end = p + decoded_len;

    if (!php_var_unserialize(&data_zval, &p, end, NULL))
    {
        efree(serialized_data);
        php_error_docref(NULL, E_WARNING, "Zypher: Failed to unserialize data for %s", filename);
        return NULL;
    }

    /* Process the array data */
    HashTable *data_ht;
    zval *contents_zval, *source_hint_zval = NULL;
    zval *namespace_zval = NULL, *classname_zval = NULL;

    if (Z_TYPE(data_zval) == IS_ARRAY && (data_ht = Z_ARRVAL(data_zval)))
    {
        /* Extract contents and metadata */
        if ((contents_zval = zend_hash_str_find(data_ht, "contents", sizeof("contents") - 1)) != NULL &&
            Z_TYPE_P(contents_zval) == IS_STRING)
        {
            source_code = estrndup(Z_STRVAL_P(contents_zval), Z_STRLEN_P(contents_zval));
        }

        /* Get source_hint (full source code for reconstruction) */
        if ((source_hint_zval = zend_hash_str_find(data_ht, "source_hint", sizeof("source_hint") - 1)) != NULL &&
            Z_TYPE_P(source_hint_zval) == IS_STRING)
        {
            source_hint = estrndup(Z_STRVAL_P(source_hint_zval), Z_STRLEN_P(source_hint_zval));
        }

        /* Get namespace */
        if ((namespace_zval = zend_hash_str_find(data_ht, "namespace", sizeof("namespace") - 1)) != NULL &&
            Z_TYPE_P(namespace_zval) == IS_STRING)
        {
            namespace = estrndup(Z_STRVAL_P(namespace_zval), Z_STRLEN_P(namespace_zval));
        }

        /* Get classname */
        if ((classname_zval = zend_hash_str_find(data_ht, "classname", sizeof("classname") - 1)) != NULL &&
            Z_TYPE_P(classname_zval) == IS_STRING)
        {
            classname = estrndup(Z_STRVAL_P(classname_zval), Z_STRLEN_P(classname_zval));
        }
    }

    /* Free the serialized data */
    efree(serialized_data);

    /* Check if we have the source code */
    if (!source_code)
    {
        zval_ptr_dtor(&data_zval);
        php_error_docref(NULL, E_WARNING, "Zypher: Failed to extract source code for %s", filename);
        return NULL;
    }

    /* Create a zend_string for the filename */
    zend_string *zs_filename = zend_string_init(filename, strlen(filename), 0);

    /* Use the enhanced source_hint (complete source code) if available */
    if (source_hint && strlen(source_hint) > 0)
    {
        /* Create a zend_string for the source code */
        zend_string *zs_source = zend_string_init(source_hint, strlen(source_hint), 0);

        /* Directly compile the complete source code with proper API parameter */
        op_array = compile_string(zs_source, filename, ZEND_COMPILE_POSITION_AT_OPEN_TAG);

        zend_string_release(zs_source);

        if (op_array)
        {
#if PHP_VERSION_ID >= 70300
            op_array->filename = zend_string_copy(zs_filename);
#else
            op_array->filename = estrndup(filename, strlen(filename));
#endif
        }
    }
    else
    {
        /* Fallback to the original source code */
        zend_string *zs_source = zend_string_init(source_code, strlen(source_code), 0);

        /* Call compile_string with proper parameters */
        op_array = compile_string(zs_source, filename, ZEND_COMPILE_POSITION_AT_OPEN_TAG);

        zend_string_release(zs_source);

        if (op_array)
        {
#if PHP_VERSION_ID >= 70300
            op_array->filename = zend_string_copy(zs_filename);
#else
            op_array->filename = estrndup(filename, strlen(filename));
#endif
        }
    }

    /* Release the filename string */
    zend_string_release(zs_filename);

    /* Add debug info if available */
    if (op_array && namespace && classname)
    {
        /* For debugging: printf("Loaded class %s in namespace %s from %s\n", classname, namespace, filename); */
    }

    /* Free allocated memory */
    if (source_code)
        efree(source_code);
    if (source_hint)
        efree(source_hint);
    if (namespace)
        efree(namespace);
    if (classname)
        efree(classname);
    zval_ptr_dtor(&data_zval);

    if (!op_array)
    {
        php_error_docref(NULL, E_WARNING, "Zypher: Failed to compile source for %s", filename);
    }

    return op_array;
}