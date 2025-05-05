#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/base64.h"
#include "ext/standard/md5.h"

#include "src/php_loader.h"
#include "decrypt.h"
#include "security.h"
#include "utils.h"

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

/* Enhanced decrypt function that handles advanced format and obfuscation */
char *decrypt_file_content(const char *encoded_content, size_t encoded_length,
                           const char *master_key, const char *filename, size_t *out_length)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    unsigned char iv[IV_LENGTH];
    unsigned char key_iv[IV_LENGTH]; /* For new format with separate IVs */
    char *decrypted = NULL;
    int outlen, tmplen;
    zend_string *decoded_str;
    char file_key[65]; /* 64 hex chars + null */
    char *encrypted_file_key = NULL;
    char *orig_filename = NULL;
    uint32_t key_length = 0;
    uint8_t filename_length = 0;
    size_t pos = 0;
    char debug_hex[128];
    int format_version = 0;
    uint32_t timestamp = 0;
    int has_byte_rotation = 0;
    char extracted_checksum[33] = {0};

    /* Debug output */
    if (DEBUG)
    {
        php_printf("DEBUG: Decrypting content of length %zu\n", encoded_length);
    }

    /* Check for Zypher signature */
    if (encoded_length < SIGNATURE_LENGTH || strncmp(encoded_content, ZYPHER_SIGNATURE, SIGNATURE_LENGTH) != 0)
    {
        if (DEBUG)
            php_printf("DEBUG: Invalid signature\n");
        return NULL;
    }

    /* Base64 decode the content after signature */
    decoded_str = php_base64_decode(
        (const unsigned char *)encoded_content + SIGNATURE_LENGTH,
        encoded_length - SIGNATURE_LENGTH);

    if (!decoded_str)
    {
        if (DEBUG)
            php_printf("DEBUG: Base64 decoding failed\n");
        return NULL;
    }

    if (DEBUG)
    {
        php_printf("DEBUG: Base64 decoded length: %zu bytes\n", ZSTR_LEN(decoded_str));
    }

    /* Handle byte rotation if present (enhanced format) */
    char *rotated_content = NULL;

    /* Check if first byte value suggests byte rotation (+7) */
    if (ZSTR_LEN(decoded_str) > 0)
    {
        /* Simple heuristic: check if first byte is likely version byte (1) rotated by +7 */
        if ((unsigned char)ZSTR_VAL(decoded_str)[0] == (1 + 7) % 256)
        {
            has_byte_rotation = 1;

            if (DEBUG)
            {
                php_printf("DEBUG: Detected byte rotation encoding\n");
            }

            /* Un-rotate bytes (reverse +7 rotation) */
            rotated_content = emalloc(ZSTR_LEN(decoded_str) + 1);
            for (size_t i = 0; i < ZSTR_LEN(decoded_str); i++)
            {
                rotated_content[i] = (char)((unsigned char)(ZSTR_VAL(decoded_str)[i] - 7) & 0xFF);
            }
            rotated_content[ZSTR_LEN(decoded_str)] = '\0';

            /* Replace decoded_str with rotated content for further processing */
            zend_string *old_str = decoded_str;
            decoded_str = zend_string_init(rotated_content, ZSTR_LEN(old_str), 0);
            zend_string_release(old_str);
            efree(rotated_content);
        }
    }

    /* Parse the enhanced format */
    pos = 0;
    unsigned char *data = (unsigned char *)ZSTR_VAL(decoded_str);
    size_t data_len = ZSTR_LEN(decoded_str);

    /* Make sure we have enough data for the version byte */
    if (data_len < pos + 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for version byte\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract format version */
    format_version = data[pos++];

    if (DEBUG)
    {
        php_printf("DEBUG: Format version: %d\n", format_version);
    }

    /* Verify expected format version */
    if (format_version != ZYPHER_FORMAT_VERSION)
    {
        if (DEBUG)
            php_printf("DEBUG: Unsupported format version %d (expected %d)\n",
                       format_version, ZYPHER_FORMAT_VERSION);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Check for timestamp */
    if (data_len < pos + 4)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for timestamp\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Extract timestamp (big endian) */
    timestamp = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
    pos += 4;

    if (DEBUG)
    {
        php_printf("DEBUG: Timestamp: %u\n", timestamp);
    }

    /* Verify license based on timestamp */
    int license_error = zypher_verify_license(NULL, timestamp);
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

    memcpy(iv, data + pos, IV_LENGTH);
    pos += IV_LENGTH;

    if (DEBUG)
    {
        char hex_iv[IV_LENGTH * 2 + 1];
        for (int i = 0; i < IV_LENGTH; i++)
            sprintf(hex_iv + i * 2, "%02x", iv[i]);
        hex_iv[IV_LENGTH * 2] = '\0';
        php_printf("DEBUG: Content IV: %s\n", hex_iv);
    }

    /* Extract key IV */
    if (data_len < pos + IV_LENGTH)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for key IV\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    memcpy(key_iv, data + pos, IV_LENGTH);
    pos += IV_LENGTH;

    if (DEBUG)
    {
        char hex_key_iv[IV_LENGTH * 2 + 1];
        for (int i = 0; i < IV_LENGTH; i++)
            sprintf(hex_key_iv + i * 2, "%02x", key_iv[i]);
        hex_key_iv[IV_LENGTH * 2] = '\0';
        php_printf("DEBUG: Key IV: %s\n", hex_key_iv);
    }

    /* Extract key length */
    if (data_len < pos + 4)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for key length\n");
        zend_string_release(decoded_str);
        return NULL;
    }

    key_length = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
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

    encrypted_file_key = emalloc(key_length + 1);
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

    filename_length = data[pos++];

    if (DEBUG)
    {
        php_printf("DEBUG: Original filename length: %u\n", filename_length);
    }

    /* Extract original filename - important for key derivation */
    if (data_len < pos + filename_length)
    {
        if (DEBUG)
            php_printf("DEBUG: Data too short for original filename\n");
        efree(encrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    orig_filename = emalloc(filename_length + 1);
    memcpy(orig_filename, data + pos, filename_length);
    orig_filename[filename_length] = '\0';
    pos += filename_length;

    if (DEBUG)
    {
        php_printf("DEBUG: Original filename: %s\n", orig_filename);
    }

    /* The rest is encrypted content */
    size_t encrypted_content_length = data_len - pos;
    if (encrypted_content_length == 0)
    {
        if (DEBUG)
            php_printf("DEBUG: No encrypted content\n");
        efree(encrypted_file_key);
        efree(orig_filename);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Derive master key from filename */
    char derived_key[65];

    /* Use original filename for key derivation, not the current one */
    zypher_derive_key(master_key, orig_filename, derived_key, 1000);

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
        efree(orig_filename);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Select AES-256-CBC cipher */
    cipher = EVP_aes_256_cbc();

    /* Decrypt the file key with derived master key */
    char *decrypted_file_key = emalloc(key_length + EVP_MAX_BLOCK_LENGTH);

    /* Initialize decryption process */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL,
                           (unsigned char *)derived_key, key_iv) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
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
        efree(orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Finalize decryption */
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted_file_key + outlen, &tmplen) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to finalize key decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    outlen += tmplen;
    decrypted_file_key[outlen] = '\0';

    if (DEBUG)
    {
        php_printf("DEBUG: Decrypted file key: %s (length: %d)\n", decrypted_file_key, outlen);
    }

    /* Now decrypt actual file content using the decrypted file key */
    EVP_CIPHER_CTX_reset(ctx);

    /* Initialize encryption with file key and content IV */
    if (EVP_DecryptInit_ex(ctx, cipher, NULL,
                           (unsigned char *)decrypted_file_key, iv) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to initialize content decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        efree(decrypted_file_key);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Allocate memory for decrypted content */
    decrypted = emalloc(encrypted_content_length + EVP_MAX_BLOCK_LENGTH + 1);

    /* Perform decryption */
    if (EVP_DecryptUpdate(ctx, (unsigned char *)decrypted, &outlen,
                          (unsigned char *)(data + pos), encrypted_content_length) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to decrypt content\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
        efree(decrypted_file_key);
        efree(decrypted);
        zend_string_release(decoded_str);
        return NULL;
    }

    /* Finalize decryption */
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted + outlen, &tmplen) != 1)
    {
        if (DEBUG)
            php_printf("DEBUG: Failed to finalize content decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        efree(encrypted_file_key);
        efree(orig_filename);
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
    memcpy(extracted_checksum, decrypted, 32);
    extracted_checksum[32] = '\0';

    /* Move the actual PHP content to the beginning */
    memmove(decrypted, decrypted + 32, outlen - 32 + 1);
    outlen -= 32;

    if (DEBUG)
    {
        php_printf("DEBUG: Extracted checksum: %s\n", extracted_checksum);
    }

    /* Verify content integrity with checksum */
    if (verify_content_integrity(decrypted, outlen, extracted_checksum) != ZYPHER_ERR_NONE)
    {
        if (DEBUG)
            php_printf("DEBUG: Content integrity check failed\n");
        efree(orig_filename);
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

    efree(orig_filename);
    zend_string_release(decoded_str);
    return decrypted;
}