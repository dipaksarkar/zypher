/**
 * Zypher PHP Encoder - Main header file
 * Defines interfaces for the encoder component
 */
#ifndef ZYPHER_ENCODER_H
#define ZYPHER_ENCODER_H

#include <stdint.h>

/* Success / failure constants */
#define ZYPHER_SUCCESS 0
#define ZYPHER_FAILURE 1

/* Encoder options structure */
typedef struct _zypher_encoder_options
{
    const char *input_file;    /* Input PHP file path */
    const char *output_file;   /* Output encoded file path */
    const char *domain_lock;   /* Domain lock (NULL for none) */
    uint32_t expire_timestamp; /* Expiration timestamp (0 for none) */
    int iteration_count;       /* Key derivation iterations */
    int debug;                 /* Debug mode flag */
    int obfuscate;             /* Apply obfuscation */
    int disable_phpinfo;       /* Block phpinfo() in encoded files */
    int anti_debug;            /* Enable anti-debugging features */
} zypher_encoder_options;

/* Function prototypes for the encoder component */

/* From encoder.c */
int zypher_encoder_init();
void zypher_encoder_shutdown();
int encode_php_file(const zypher_encoder_options *options);

/* From encoder_crypto.c */
void calculate_content_checksum(const char *content, size_t length, char *output);
char *encrypt_content(const char *content, size_t content_len, const char *key,
                      unsigned char *iv, size_t *out_len);
char *derive_encryption_key(const char *master_key, const char *filename, int iterations);

/* From encoder_opcode.c */
int compile_php_to_opcodes(const char *source_code, const char *filename, char **output, size_t *output_len);

/* From encoder_utils.c */
char *read_file_contents(const char *filename, size_t *size);
char *run_command(const char *command, size_t *output_size);
char *base64_encode(const unsigned char *input, size_t length);
int create_stub_file(const char *filename, const char *encoded_content, size_t content_len,
                     const zypher_encoder_options *options);

#endif /* ZYPHER_ENCODER_H */