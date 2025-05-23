#ifndef PHP_ZYPHER_H
#define PHP_ZYPHER_H

extern zend_module_entry zypher_module_entry;
#define phpext_zypher_ptr &zypher_module_entry

#define PHP_ZYPHER_VERSION "2.0.0"

/* For compatibility with PHP thread safety */
#ifdef ZTS
#include "TSRM.h"
#endif

/* Define the extension globals */
ZEND_BEGIN_MODULE_GLOBALS(zypher)
char *license_domain;               /* Licensed domain */
time_t license_expiry;              /* License expiration timestamp */
unsigned char anti_tamper_hash[32]; /* Hash to verify extension integrity */
int self_healing;                   /* Enable self-healing code */
HashTable *opcode_cache;            /* Cache for decoded opcodes */
ZEND_END_MODULE_GLOBALS(zypher)

/* Define debug macro - use compile-time flag instead of runtime configuration */
#undef DEBUG
#ifdef ENABLE_ZYPHER_DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#ifdef ENABLE_ZYPHER_DEBUG
/* Disable debugger protection in debug mode for development ease */
#define ZYPHER_DEBUGGER_PROTECTION 0
#else
/* Always enable debugger protection in release builds */
#define ZYPHER_DEBUGGER_PROTECTION 1
#endif

/* Define a master key constant (used to decrypt per-file keys) */
#define ZYPHER_MASTER_KEY "Zypher-Master-Key-X7pQ9r2s"
#define ZYPHER_SIGNATURE "ZYPH02" // Updated to version 2
#define SIGNATURE_LENGTH 6
#define IV_LENGTH 16
#define KEY_LENGTH 32
#define MAX_KEY_ITERATIONS 5000

/* File format versions */
#define ZYPHER_FORMAT_VERSION_V1 1
#define ZYPHER_FORMAT_VERSION_V2 2

/* Format types */
#define ZYPHER_FORMAT_SOURCE 1
#define ZYPHER_FORMAT_OPCODE 2

/* Define security flags */
#define ZYPHER_FLAG_EXPIRE 0x0001      /* Content has expiry date */
#define ZYPHER_FLAG_DEBUG_PROT 0x0002  /* Anti-debug protection enabled */
#define ZYPHER_FLAG_DOMAIN_LOCK 0x0004 /* Domain locked content */
#define ZYPHER_FLAG_CHECKSUM 0x0008    /* Content includes checksum */
#define ZYPHER_FLAG_OBFUSCATED 0x0010  /* Content is obfuscated */
#define ZYPHER_FLAG_BYTE_ROTATE 0x0020 /* Content bytes are rotated */

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

/* Access extension globals */
#ifdef ZTS
#define ZYPHER_G(v) ZEND_TSRMG(zypher_globals_id, zend_zypher_globals *, v)
#else
#define ZYPHER_G(v) (zypher_globals.v)
#endif

/* Function declarations */
zend_op_array *zypher_compile_file(zend_file_handle *file_handle, int type);

/* Security-related functions */
int zypher_verify_integrity(void);
int zypher_check_debugger(void);
int zypher_verify_license(const char *domain, time_t timestamp);
void zypher_derive_key(const char *master_key, const char *filename, char *output_key, int iterations);
int verify_content_integrity(const char *content, size_t length, const char *expected_checksum);
void calculate_content_checksum(const char *content, size_t length, char *output);

/* Opcode handling functions */
zend_op_array *zypher_load_opcodes(zval *opcodes, zend_string *filename);
void zypher_free_opcode_cache(void);

/* PHP functions exported by the extension */
PHP_FUNCTION(zypher_decode_string);

#endif /* PHP_ZYPHER_H */