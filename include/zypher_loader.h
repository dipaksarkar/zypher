#ifndef ZYPHER_LOADER_H
#define ZYPHER_LOADER_H

#include "zypher_common.h"

extern zend_module_entry zypher_module_entry;
#define phpext_zypher_ptr &zypher_module_entry

/* Use the version from php_zypher.h if available, otherwise define it */
#ifndef PHP_ZYPHER_VERSION
#ifdef ZYPHER_VERSION
#define PHP_ZYPHER_VERSION ZYPHER_VERSION
#else
#define PHP_ZYPHER_VERSION "1.0.0"
#endif
#endif

/* For compatibility with PHP thread safety */
#ifdef ZTS
#include "TSRM.h"
#endif

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

/* File metadata structure used throughout the extension */
typedef struct _zypher_file_metadata
{
    unsigned char format_version;
    unsigned char format_type;
    uint32_t timestamp;
    unsigned char content_iv[16];
    unsigned char key_iv[16];
    char *file_key;
    char *orig_filename;
    char checksum[33];
} zypher_file_metadata;

#endif /* ZYPHER_LOADER_H */