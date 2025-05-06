#ifndef PHP_ZYPHER_H
#define PHP_ZYPHER_H

#include "../include/zypher_shared.h"

extern zend_module_entry zypher_module_entry;
#define phpext_zypher_ptr &zypher_module_entry

#define PHP_ZYPHER_VERSION ZYPHER_VERSION

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