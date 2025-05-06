#ifndef ZYPHER_ENCODER_H
#define ZYPHER_ENCODER_H

#include "../../include/zypher_shared.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

/* Version number (should match the shared version) */
#define ZYPHER_ENCODER_VERSION ZYPHER_VERSION

/* Program options */
typedef struct
{
    char *source_path;
    char *output_path;
    char *master_key;
    char **exclude_patterns;
    int exclude_count;
    int obfuscate;
    int verbose;
    int show_help;
    int show_version;
} zypher_options_t;

/* File metadata */
typedef struct
{
    char *filename;
    char *path;
    size_t size;
    time_t mtime;
    int is_directory;
} zypher_file_t;

/* Function prototypes */

/* Initialization and cleanup */
int zypher_encoder_init(void);
void zypher_encoder_cleanup(void);

/* Command line parsing */
int zypher_parse_options(int argc, char **argv, zypher_options_t *options);
void zypher_print_help(const char *program_name);
void zypher_print_version(void);

/* File handling */
zypher_file_t *zypher_get_file_info(const char *path);
char *zypher_read_file_contents(const char *path, size_t *size);
int zypher_write_file_contents(const char *path, const char *content, size_t size);
void zypher_free_file_info(zypher_file_t *file);

/* Directory handling */
int zypher_create_directory(const char *path);
int zypher_process_directory(const char *source_dir, const char *output_dir, zypher_options_t *options);
int zypher_is_excluded(const char *path, char **exclude_patterns, int exclude_count);

/* Encoding */
int zypher_encode_file(const char *source_path, const char *output_path, zypher_options_t *options);
char *zypher_obfuscate_code(const char *code, size_t *size);
char *zypher_encrypt_content(const char *content, size_t content_size,
                             const char *key, unsigned char *iv,
                             size_t *encrypted_size);

/* Utility functions */
void zypher_derive_key(const char *master_key, const char *filename, char *output_key, int iterations);
char *zypher_calculate_checksum(const char *content, size_t size);
char *zypher_base64_encode(const unsigned char *input, size_t length);
int zypher_is_php_file(const char *path);

/* Key management */
char *zypher_generate_random_key(int length);
int zypher_save_master_key(const char *key, const char *path);
char *zypher_load_master_key(const char *path);

#endif /* ZYPHER_ENCODER_H */