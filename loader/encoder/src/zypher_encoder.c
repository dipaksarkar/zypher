#include "../include/zypher_encoder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <libgen.h> /* For basename() */

#ifdef __APPLE__
#include <limits.h>
#include <sys/syslimits.h>
#else
#include <linux/limits.h>
#endif

/* Path to store the master key, relative to the encoder */
#define MASTER_KEY_FILE ".zypher_key"

/* Initialize OpenSSL and other resources */
int zypher_encoder_init(void)
{
    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Seed the random number generator */
    srand((unsigned int)time(NULL));

    return 1;
}

/* Cleanup OpenSSL and free resources */
void zypher_encoder_cleanup(void)
{
    /* Clean up OpenSSL */
    EVP_cleanup();
    ERR_free_strings();
}

/* Parse command line options */
int zypher_parse_options(int argc, char **argv, zypher_options_t *options)
{
    int option;
    int option_index = 0;
    char *token;

    /* Define the long options */
    static struct option long_options[] = {
        {"exclude", required_argument, 0, 'e'},
        {"obfuscate", no_argument, 0, 'o'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0}};

    /* Initialize options with default values */
    memset(options, 0, sizeof(zypher_options_t));

    /* Parse options */
    while ((option = getopt_long(argc, argv, "e:ovhV", long_options, &option_index)) != -1)
    {
        switch (option)
        {
        case 'e':
            /* Parse comma-separated exclude patterns */
            token = strtok(optarg, ",");
            while (token != NULL)
            {
                options->exclude_patterns = realloc(options->exclude_patterns,
                                                    (options->exclude_count + 1) * sizeof(char *));
                if (options->exclude_patterns == NULL)
                {
                    fprintf(stderr, "Memory allocation error\n");
                    return 0;
                }

                options->exclude_patterns[options->exclude_count] = strdup(token);
                options->exclude_count++;
                token = strtok(NULL, ",");
            }
            break;

        case 'o':
            options->obfuscate = 1;
            break;

        case 'v':
            options->verbose = 1;
            break;

        case 'h':
            options->show_help = 1;
            return 1;

        case 'V':
            options->show_version = 1;
            return 1;

        case '?':
            /* getopt_long already printed an error message */
            return 0;

        default:
            return 0;
        }
    }

    /* Check that we have at least the source path */
    if (optind >= argc)
    {
        fprintf(stderr, "Error: Missing source path\n");
        return 0;
    }

    /* Get the source path (required) */
    options->source_path = strdup(argv[optind++]);

    /* Get the output path (optional) */
    if (optind < argc)
    {
        options->output_path = strdup(argv[optind]);
    }
    else
    {
        /* If no output path is specified, use source_path with _encoded suffix */
        zypher_file_t *file_info = zypher_get_file_info(options->source_path);

        if (!file_info)
        {
            fprintf(stderr, "Error: Could not access source path %s\n", options->source_path);
            return 0;
        }

        if (file_info->is_directory)
        {
            /* For directories, append _encoded to the directory name */
            options->output_path = malloc(strlen(options->source_path) + 10); /* +10 for "_encoded\0" */
            if (options->output_path)
            {
                sprintf(options->output_path, "%s_encoded", options->source_path);
            }
        }
        else
        {
            /* For files, add _encoded before the extension */
            char *filename_copy = strdup(options->source_path);
            char *dir = dirname(filename_copy);
            char *basename_copy = strdup(options->source_path);
            char *base = basename(basename_copy);

            /* Find the extension */
            char *ext = strrchr(base, '.');
            if (ext && ext != base)
            {
                /* Has extension */
                *ext = '\0'; /* Temporarily cut the string at the dot */
                options->output_path = malloc(strlen(dir) + strlen(base) + strlen(ext) + 10);
                if (options->output_path)
                {
                    sprintf(options->output_path, "%s/%s_encoded%s", dir, base, ext);
                }
            }
            else
            {
                /* No extension */
                options->output_path = malloc(strlen(dir) + strlen(base) + 10);
                if (options->output_path)
                {
                    sprintf(options->output_path, "%s/%s_encoded", dir, base);
                }
            }

            free(filename_copy);
            free(basename_copy);
        }

        zypher_free_file_info(file_info);
    }

    if (!options->output_path)
    {
        fprintf(stderr, "Error: Memory allocation for output path failed\n");
        return 0;
    }

    return 1;
}

/* Print help message */
void zypher_print_help(const char *program_name)
{
    printf("Zypher Encoder v%s\n\n", ZYPHER_ENCODER_VERSION);
    printf("Usage: %s <source_path> [output_path] [options]\n\n", program_name);
    printf("Options:\n");
    printf("  -e, --exclude=<pattern1>,<pattern2>   Exclude files matching patterns\n");
    printf("  -o, --obfuscate                       Enable code obfuscation\n");
    printf("  -v, --verbose                         Show verbose output\n");
    printf("  -h, --help                            Show this help message\n");
    printf("  -V, --version                         Show version information\n\n");
    printf("If output_path is not specified, it will use source_path with '_encoded' suffix\n");
    printf("<source_path> and [output_path] can be either files or directories\n");
}

/* Print version information */
void zypher_print_version(void)
{
    printf("Zypher Encoder v%s\n", ZYPHER_ENCODER_VERSION);
}

/* Get file information */
zypher_file_t *zypher_get_file_info(const char *path)
{
    struct stat st;
    zypher_file_t *file;

    if (stat(path, &st) != 0)
    {
        return NULL;
    }

    file = malloc(sizeof(zypher_file_t));
    if (!file)
    {
        return NULL;
    }

    file->path = strdup(path);

    /* Extract filename from path */
    char *path_copy = strdup(path);
    char *filename = basename(path_copy);
    file->filename = strdup(filename);
    free(path_copy);

    file->size = st.st_size;
    file->mtime = st.st_mtime;
    file->is_directory = S_ISDIR(st.st_mode);

    return file;
}

/* Free file information structure */
void zypher_free_file_info(zypher_file_t *file)
{
    if (file)
    {
        if (file->path)
            free(file->path);
        if (file->filename)
            free(file->filename);
        free(file);
    }
}

/* Read file contents */
char *zypher_read_file_contents(const char *path, size_t *size)
{
    FILE *file;
    char *buffer;
    size_t file_size;
    size_t read_size;

    file = fopen(path, "rb");
    if (!file)
    {
        return NULL;
    }

    /* Determine file size */
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    /* Allocate buffer */
    buffer = malloc(file_size + 1);
    if (!buffer)
    {
        fclose(file);
        return NULL;
    }

    /* Read file content */
    read_size = fread(buffer, 1, file_size, file);
    fclose(file);

    if (read_size != file_size)
    {
        free(buffer);
        return NULL;
    }

    /* Null terminate buffer */
    buffer[file_size] = '\0';

    if (size)
    {
        *size = file_size;
    }

    return buffer;
}

/* Write file contents */
int zypher_write_file_contents(const char *path, const char *content, size_t size)
{
    FILE *file;
    size_t written_size;

    /* Ensure directory exists for the file */
    char *path_copy = strdup(path);
    char *dir = dirname(path_copy);
    zypher_create_directory(dir);
    free(path_copy);

    file = fopen(path, "wb");
    if (!file)
    {
        return 0;
    }

    written_size = fwrite(content, 1, size, file);
    fclose(file);

    return (written_size == size);
}

/* Create directory (recursively) */
int zypher_create_directory(const char *path)
{
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    /* Copy path to editable buffer */
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);

    /* Remove trailing slash if present */
    if (tmp[len - 1] == '/')
    {
        tmp[len - 1] = '\0';
    }

    /* Create directories recursively */
    for (p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0'; /* Temporarily terminate */

            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
            {
                return 0;
            }

            *p = '/'; /* Restore */
        }
    }

    /* Create final directory */
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
    {
        return 0;
    }

    return 1;
}

/* Check if file is a PHP file based on extension */
int zypher_is_php_file(const char *path)
{
    const char *ext = strrchr(path, '.');
    if (!ext)
    {
        return 0;
    }

    return (strcasecmp(ext, ".php") == 0 ||
            strcasecmp(ext, ".phtml") == 0 ||
            strcasecmp(ext, ".php5") == 0 ||
            strcasecmp(ext, ".php7") == 0);
}

/* Check if a file matches any exclude pattern */
int zypher_is_excluded(const char *path, char **exclude_patterns, int exclude_count)
{
    int i;

    if (!exclude_patterns || exclude_count <= 0)
    {
        return 0;
    }

    for (i = 0; i < exclude_count; i++)
    {
        /* Simple pattern matching (could be extended with regex) */
        if (strstr(path, exclude_patterns[i]))
        {
            return 1;
        }
    }

    return 0;
}

/* Process a directory and encode all PHP files */
int zypher_process_directory(const char *source_dir, const char *output_dir, zypher_options_t *options)
{
    DIR *dir;
    struct dirent *entry;
    char source_path[PATH_MAX];
    char output_path[PATH_MAX];
    zypher_file_t *file_info;
    int success = 1;

    /* Create output directory */
    if (!zypher_create_directory(output_dir))
    {
        fprintf(stderr, "Error: Failed to create output directory: %s\n", output_dir);
        return 0;
    }

    dir = opendir(source_dir);
    if (!dir)
    {
        fprintf(stderr, "Error: Failed to open directory: %s\n", source_dir);
        return 0;
    }

    while ((entry = readdir(dir)) != NULL)
    {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        /* Create full source path */
        snprintf(source_path, PATH_MAX, "%s/%s", source_dir, entry->d_name);

        /* Skip if file matches exclude pattern */
        if (zypher_is_excluded(source_path, options->exclude_patterns, options->exclude_count))
        {
            if (options->verbose)
            {
                printf("Skipping excluded file: %s\n", source_path);
            }
            continue;
        }

        /* Get file info */
        file_info = zypher_get_file_info(source_path);
        if (!file_info)
        {
            fprintf(stderr, "Warning: Could not get info for %s\n", source_path);
            success = 0;
            continue;
        }

        /* Create full output path */
        snprintf(output_path, PATH_MAX, "%s/%s", output_dir, entry->d_name);

        if (file_info->is_directory)
        {
            /* Process subdirectory recursively */
            if (!zypher_process_directory(source_path, output_path, options))
            {
                success = 0;
            }
        }
        else if (zypher_is_php_file(source_path))
        {
            /* Encode PHP file */
            if (!zypher_encode_file(source_path, output_path, options))
            {
                fprintf(stderr, "Error: Failed to encode file: %s\n", source_path);
                success = 0;
            }
            else if (options->verbose)
            {
                printf("Successfully encoded: %s -> %s\n", source_path, output_path);
            }
        }
        else
        {
            /* Copy non-PHP file */
            char *content;
            size_t size;

            content = zypher_read_file_contents(source_path, &size);
            if (!content)
            {
                fprintf(stderr, "Error: Failed to read file: %s\n", source_path);
                success = 0;
            }
            else
            {
                if (!zypher_write_file_contents(output_path, content, size))
                {
                    fprintf(stderr, "Error: Failed to write file: %s\n", output_path);
                    success = 0;
                }
                else if (options->verbose)
                {
                    printf("Copied: %s -> %s\n", source_path, output_path);
                }

                free(content);
            }
        }

        zypher_free_file_info(file_info);
    }

    closedir(dir);
    return success;
}

/* Generate a random key */
char *zypher_generate_random_key(int length)
{
    const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    int chars_len = strlen(chars);
    unsigned char *key = malloc(length + 1);
    int i;

    if (!key)
    {
        return NULL;
    }

    /* Use OpenSSL for better random bytes */
    if (RAND_bytes(key, length) != 1)
    {
        /* Fall back to less secure rand() */
        for (i = 0; i < length; i++)
        {
            key[i] = chars[rand() % chars_len];
        }
    }
    else
    {
        /* Map random bytes to character set */
        for (i = 0; i < length; i++)
        {
            key[i] = chars[key[i] % chars_len];
        }
    }

    key[length] = '\0';
    return (char *)key;
}

/* Save master key to file */
int zypher_save_master_key(const char *key, const char *path)
{
    return zypher_write_file_contents(path, key, strlen(key));
}

/* Load master key from file */
char *zypher_load_master_key(const char *path)
{
    return zypher_read_file_contents(path, NULL);
}

/* Basic MD5 checksum calculation */
char *zypher_calculate_checksum(const char *content, size_t size)
{
    EVP_MD_CTX *mdctx;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    char *md5_str;
    int i;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        return NULL;
    }

    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, content, size);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    /* Convert binary MD5 to hex string */
    md5_str = malloc(md_len * 2 + 1);
    if (!md5_str)
    {
        return NULL;
    }

    for (i = 0; i < md_len; i++)
    {
        sprintf(&md5_str[i * 2], "%02x", md_value[i]);
    }

    return md5_str;
}

/* Base64 encoding */
char *zypher_base64_encode(const unsigned char *input, size_t length)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    /* Ignore newlines - write everything in one line */
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    /* Add null terminator */
    char *base64_encoded = malloc(bufferPtr->length + 1);
    if (!base64_encoded)
    {
        BIO_free_all(bio);
        return NULL;
    }

    memcpy(base64_encoded, bufferPtr->data, bufferPtr->length);
    base64_encoded[bufferPtr->length] = '\0';

    BIO_free_all(bio);

    return base64_encoded;
}

/* Derive a key from master key and filename */
void zypher_derive_key(const char *master_key, const char *filename, char *output_key, int iterations)
{
    unsigned int derive_len = 32;
    unsigned char derived_key[32];
    char salt[100];
    char *md5_filename;
    char *combined_data;
    unsigned char *buffer;
    int i;

    /* Generate MD5 of filename */
    EVP_MD_CTX *md5_ctx = EVP_MD_CTX_new();
    unsigned char md5_value[EVP_MAX_MD_SIZE];
    unsigned int md5_len;

    EVP_DigestInit_ex(md5_ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(md5_ctx, filename, strlen(filename));
    EVP_DigestFinal_ex(md5_ctx, md5_value, &md5_len);
    EVP_MD_CTX_free(md5_ctx);

    /* Convert MD5 to hex string */
    md5_filename = malloc(md5_len * 2 + 1);
    if (!md5_filename)
    {
        return;
    }

    for (i = 0; i < md5_len; i++)
    {
        sprintf(&md5_filename[i * 2], "%02x", md5_value[i]);
    }

    /* Create salt string */
    snprintf(salt, sizeof(salt), "ZypherSalt-%s", md5_filename);

    /* Create combined data */
    combined_data = malloc(strlen(filename) + strlen(salt) + 1);
    if (!combined_data)
    {
        free(md5_filename);
        return;
    }

    strcpy(combined_data, filename);
    strcat(combined_data, salt);

    /* Perform initial HMAC */
    HMAC(EVP_sha256(), master_key, strlen(master_key),
         (unsigned char *)combined_data, strlen(combined_data),
         derived_key, &derive_len);

    /* Perform iterations */
    for (i = 0; i < iterations; i++)
    {
        /* Allocate buffer for iteration */
        buffer = malloc(derive_len + strlen(salt) + 1);
        if (!buffer)
        {
            free(md5_filename);
            free(combined_data);
            return;
        }

        /* Copy derived key */
        memcpy(buffer, derived_key, derive_len);

        /* Add salt */
        memcpy(buffer + derive_len, salt, strlen(salt));

        /* Add iteration counter */
        buffer[derive_len + strlen(salt)] = (unsigned char)(i & 0xFF);

        /* Perform HMAC */
        HMAC(EVP_sha256(), master_key, strlen(master_key),
             buffer, derive_len + strlen(salt) + 1,
             derived_key, &derive_len);

        free(buffer);
    }

    /* Convert to hex string */
    for (i = 0; i < 32; i++)
    {
        sprintf(&output_key[i * 2], "%02x", derived_key[i]);
    }
    output_key[64] = '\0';

    /* Clean up */
    free(md5_filename);
    free(combined_data);
}

/* Apply basic PHP code obfuscation */
char *zypher_obfuscate_code(const char *code, size_t *size)
{
    /* This is a very simple placeholder for real obfuscation
       In a real implementation, you would want to:
       1. Parse the PHP code properly
       2. Rename variables
       3. Add junk code
       4. Encode strings
       5. Shuffle code blocks where possible
       etc.
    */

    /* For now, just add a comment to indicate obfuscation */
    char *obfuscated = malloc(strlen(code) + 50);
    if (!obfuscated)
    {
        return NULL;
    }

    strcpy(obfuscated, "<?php /* Obfuscated by Zypher Encoder " ZYPHER_ENCODER_VERSION " */ ?>\n");
    strcat(obfuscated, code);

    if (size)
    {
        *size = strlen(obfuscated);
    }

    return obfuscated;
}

/* Encrypt content with AES-256-CBC */
char *zypher_encrypt_content(const char *content, size_t content_size,
                             const char *key, unsigned char *iv,
                             size_t *encrypted_size)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char *ciphertext;

    /* Allocate buffer for encrypted data (original + block size for padding) */
    ciphertext = malloc(content_size + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext)
    {
        return NULL;
    }

    /* Create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        free(ciphertext);
        return NULL;
    }

    /* Initialize the encryption operation */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                           (unsigned char *)key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)content,
                          content_size) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len = len;

    /* Finalize the encryption */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (encrypted_size)
    {
        *encrypted_size = ciphertext_len;
    }

    return (char *)ciphertext;
}

/* Encode a single PHP file */
int zypher_encode_file(const char *source_path, const char *output_path, zypher_options_t *options)
{
    char *content;
    size_t content_size;
    char *obfuscated_content = NULL;
    char *checksum;
    char *content_with_checksum;
    size_t content_with_checksum_size;
    char file_key[65];
    unsigned char content_iv[IV_LENGTH];
    unsigned char key_iv[IV_LENGTH];
    char *encrypted_content;
    size_t encrypted_size;
    uint32_t timestamp;
    char *final_content;
    size_t final_size;
    char *base64_content;
    char *rotated_content;
    size_t rotated_size;
    int result = 0;
    char *temp_buffer;
    char *basename_copy;
    char *base_filename;

    /* Read source file */
    content = zypher_read_file_contents(source_path, &content_size);
    if (!content)
    {
        fprintf(stderr, "Error: Failed to read file: %s\n", source_path);
        return 0;
    }

    /* Apply obfuscation if enabled */
    if (options->obfuscate)
    {
        if (options->verbose)
        {
            printf("Applying obfuscation to %s\n", source_path);
        }

        obfuscated_content = zypher_obfuscate_code(content, &content_size);
        if (obfuscated_content)
        {
            free(content);
            content = obfuscated_content;
        }
        else
        {
            fprintf(stderr, "Warning: Failed to obfuscate %s\n", source_path);
        }
    }

    /* Calculate checksum of the content */
    checksum = zypher_calculate_checksum(content, content_size);
    if (!checksum)
    {
        fprintf(stderr, "Error: Failed to calculate checksum for %s\n", source_path);
        free(content);
        return 0;
    }

    /* Prepend checksum to content */
    content_with_checksum_size = strlen(checksum) + content_size;
    content_with_checksum = malloc(content_with_checksum_size);
    if (!content_with_checksum)
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(content);
        free(checksum);
        return 0;
    }

    memcpy(content_with_checksum, checksum, strlen(checksum));
    memcpy(content_with_checksum + strlen(checksum), content, content_size);

    /* Generate random IVs */
    if (RAND_bytes(content_iv, IV_LENGTH) != 1 ||
        RAND_bytes(key_iv, IV_LENGTH) != 1)
    {
        fprintf(stderr, "Error: Failed to generate random IVs\n");
        free(content);
        free(checksum);
        free(content_with_checksum);
        return 0;
    }

    /* Get base filename for key derivation */
    basename_copy = strdup(source_path);
    base_filename = basename(basename_copy);

    /* Derive file key */
    zypher_derive_key(options->master_key, base_filename, file_key, MAX_KEY_ITERATIONS);

    free(basename_copy);

    /* Encrypt content */
    encrypted_content = zypher_encrypt_content(content_with_checksum,
                                               content_with_checksum_size,
                                               file_key, content_iv,
                                               &encrypted_size);

    if (!encrypted_content)
    {
        fprintf(stderr, "Error: Encryption failed for %s\n", source_path);
        free(content);
        free(checksum);
        free(content_with_checksum);
        return 0;
    }

    /* Clean up intermediate buffers */
    free(content);
    free(checksum);
    free(content_with_checksum);

    /* Create timestamp (current time) */
    timestamp = (uint32_t)time(NULL);

    /* Assemble the final encoded file */
    final_size = 2 + 4 + IV_LENGTH * 2 + 4 + strlen(file_key) + 1 + strlen(base_filename) + encrypted_size;
    final_content = malloc(final_size);
    if (!final_content)
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(encrypted_content);
        return 0;
    }

    /* Fill the header */
    temp_buffer = final_content;

    /* Format version and type */
    *temp_buffer++ = ZYPHER_FORMAT_VERSION;
    *temp_buffer++ = ZYPHER_FORMAT_OPCODE;

    /* Timestamp (big endian) */
    *temp_buffer++ = (timestamp >> 24) & 0xFF;
    *temp_buffer++ = (timestamp >> 16) & 0xFF;
    *temp_buffer++ = (timestamp >> 8) & 0xFF;
    *temp_buffer++ = timestamp & 0xFF;

    /* Content IV */
    memcpy(temp_buffer, content_iv, IV_LENGTH);
    temp_buffer += IV_LENGTH;

    /* Key IV */
    memcpy(temp_buffer, key_iv, IV_LENGTH);
    temp_buffer += IV_LENGTH;

    /* File key length */
    uint32_t key_length = strlen(file_key);
    *temp_buffer++ = (key_length >> 24) & 0xFF;
    *temp_buffer++ = (key_length >> 16) & 0xFF;
    *temp_buffer++ = (key_length >> 8) & 0xFF;
    *temp_buffer++ = key_length & 0xFF;

    /* File key */
    memcpy(temp_buffer, file_key, key_length);
    temp_buffer += key_length;

    /* Original filename length */
    uint8_t filename_length = strlen(base_filename);
    *temp_buffer++ = filename_length;

    /* Original filename */
    memcpy(temp_buffer, base_filename, filename_length);
    temp_buffer += filename_length;

    /* Encrypted content */
    memcpy(temp_buffer, encrypted_content, encrypted_size);

    /* Apply byte rotation */
    rotated_size = final_size;
    rotated_content = malloc(rotated_size);
    if (!rotated_content)
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(final_content);
        free(encrypted_content);
        return 0;
    }

    for (size_t i = 0; i < final_size; i++)
    {
        rotated_content[i] = (final_content[i] + BYTE_ROTATION_OFFSET) & 0xFF;
    }

    /* Base64 encode */
    base64_content = zypher_base64_encode((unsigned char *)rotated_content, rotated_size);
    if (!base64_content)
    {
        fprintf(stderr, "Error: Base64 encoding failed\n");
        free(final_content);
        free(encrypted_content);
        free(rotated_content);
        return 0;
    }

    /* Generate final file content with signature */
    char *output_content;
    size_t output_size = strlen("<?php /* Zypher Encoded File */ ?>\n") +
                         SIGNATURE_LENGTH + strlen(base64_content) + 1;

    output_content = malloc(output_size);
    if (!output_content)
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(final_content);
        free(encrypted_content);
        free(rotated_content);
        free(base64_content);
        return 0;
    }

    sprintf(output_content, "<?php /* Zypher Encoded File */ ?>\n%s%s",
            ZYPHER_SIGNATURE, base64_content);

    /* Write to output file */
    result = zypher_write_file_contents(output_path, output_content, strlen(output_content));

    /* Clean up */
    free(final_content);
    free(encrypted_content);
    free(rotated_content);
    free(base64_content);
    free(output_content);

    return result;
}