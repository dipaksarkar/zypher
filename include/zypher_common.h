/**
 * Shared header file with common definitions for both Zypher Encoder and Loader
 * This file ensures consistency between the encoder and loader components
 */
#ifndef ZYPHER_COMMON_H
#define ZYPHER_COMMON_H

/* Version information */
#define ZYPHER_VERSION "1.0.0"

/* File format identifiers */
#define ZYPHER_SIGNATURE "ZYPH01" // Version 1.0 signature
#define SIGNATURE_LENGTH 6
#define ZYPHER_FORMAT_VERSION 1
#define ZYPHER_FORMAT_OPCODE 1

/* Encryption constants */
#define IV_LENGTH 16
#define KEY_LENGTH 32
#define MAX_KEY_ITERATIONS 5000
#define BYTE_ROTATION_OFFSET 7

/* Error codes */
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

#endif /* ZYPHER_COMMON_H*/