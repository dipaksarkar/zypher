/**
 * Zypher PHP Encoder/Loader - Common Definitions
 * Shared between encoder and loader components
 */
#ifndef ZYPHER_COMMON_H
#define ZYPHER_COMMON_H

/* Version information */
#define ZYPHER_VERSION "1.0.0"
#define ZYPHER_API_VERSION 1.0
#define ZYPHER_BANNER "Zypher PHP Encoder/Loader v" ZYPHER_VERSION " (C) Zypher Team"

/* File format identifiers */
#define ZYPHER_SIGNATURE "ZYPH01"
#define SIGNATURE_LENGTH 6
#define ZYPHER_FORMAT_VERSION 1
#define ZYPHER_FORMAT_OPCODE 1

/* Encryption constants */
#define IV_LENGTH 16
#define KEY_LENGTH 32
#define DEFAULT_ITERATION_COUNT 5000
#define BYTE_ROTATION_OFFSET 7

/* Security levels */
#define ZYPHER_SECURITY_NONE 0
#define ZYPHER_SECURITY_LOW 1
#define ZYPHER_SECURITY_MEDIUM 2
#define ZYPHER_SECURITY_HIGH 3

/* Environment checks */
#define ZYPHER_ENV_PRODUCTION "production"
#define ZYPHER_ENV_DEVELOPMENT "development"
#define ZYPHER_ENV_TESTING "testing"

/* Opcodes buffer size */
#define ZYPHER_BUFFER_SIZE 8192

/* Error codes */
#define ZYPHER_ERROR_NONE 0
#define ZYPHER_ERROR_FILE_ACCESS 1
#define ZYPHER_ERROR_INVALID_FORMAT 2
#define ZYPHER_ERROR_DECRYPT_FAILED 3
#define ZYPHER_ERROR_LICENSE_EXPIRED 4
#define ZYPHER_ERROR_DOMAIN_MISMATCH 5
#define ZYPHER_ERROR_TAMPERING 6
#define ZYPHER_ERROR_MEMORY 7
#define ZYPHER_ERROR_INTERNAL 8
#define ZYPHER_ERROR_EXECUTION 9
#define ZYPHER_ERROR_UNSUPPORTED 10
#define ZYPHER_ERR_NONE 0
#define ZYPHER_ERR_CORRUPT 1
#define ZYPHER_ERR_EXPIRED 2
#define ZYPHER_ERR_DOMAIN 3
#define ZYPHER_ERR_TAMPERED 4
#define ZYPHER_ERR_DEBUG 5
#define ZYPHER_ERR_UNKNOWN 99
#define ZYPHER_ERR_INVALID_FILE 1
#define ZYPHER_ERR_DECRYPT_FAILED 2
#define ZYPHER_ERR_INTEGRITY 3
#define ZYPHER_ERR_DEBUGGER 6
#define ZYPHER_ERR_OPCODE 7

/* Security flags */
#define ZYPHER_FLAG_EXPIRE 0x0001      /* Content has expiry date */
#define ZYPHER_FLAG_DEBUG_PROT 0x0002  /* Anti-debug protection enabled */
#define ZYPHER_FLAG_DOMAIN_LOCK 0x0004 /* Domain locked content */
#define ZYPHER_FLAG_CHECKSUM 0x0008    /* Content includes checksum */
#define ZYPHER_FLAG_OBFUSCATED 0x0010  /* Content is obfuscated */
#define ZYPHER_FLAG_BYTE_ROTATE 0x0020 /* Content bytes are rotated */

/* Metadata size limits */
#define ZYPHER_MAX_METADATA_SIZE 4096
#define ZYPHER_MAX_FILENAME_LEN 255
#define ZYPHER_MAX_DOMAIN_LEN 255

/* File format header */
typedef struct _zypher_file_header
{
    uint8_t format_version;       /* Zypher format version */
    uint8_t format_type;          /* Opcode or source format */
    uint32_t timestamp;           /* Creation timestamp */
    unsigned char content_iv[16]; /* IV for content encryption */
    unsigned char key_iv[16];     /* IV for key encryption */
    uint32_t key_length;          /* Length of encrypted file key */
    char *encrypted_key;          /* Encrypted file-specific key */
    uint8_t filename_length;      /* Length of original filename */
    char *original_filename;      /* Original filename */
    uint8_t domain_length;        /* Length of domain lock (0 = none) */
    char *domain_lock;            /* Domain restriction */
    uint32_t expire_timestamp;    /* Expiration timestamp (0 = none) */
} zypher_file_header;

/* Debug hook - can be specialized by encoder or loader */
#ifndef ZYPHER_DEBUG
#ifdef DEBUG
#define ZYPHER_DEBUG(msg, ...) fprintf(stderr, "[ZYPHER] " msg "\n", ##__VA_ARGS__)
#else
#define ZYPHER_DEBUG(msg, ...)
#endif
#endif

#endif /* ZYPHER_COMMON_H */