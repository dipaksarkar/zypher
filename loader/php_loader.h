#ifndef PHP_ZYPHER_H
#define PHP_ZYPHER_H

extern zend_module_entry zypher_module_entry;
#define phpext_zypher_ptr &zypher_module_entry

#define PHP_ZYPHER_VERSION "1.3.0"

/* Define debug mode */
#ifndef DEBUG
#define DEBUG 0
#endif

/* For compatibility with PHP thread safety */
#ifdef ZTS
#include "TSRM.h"
#endif

/* Define the extension globals */
ZEND_BEGIN_MODULE_GLOBALS(zypher)
ZEND_END_MODULE_GLOBALS(zypher)

/* Define a master key constant (used to decrypt per-file keys) */
#define ZYPHER_MASTER_KEY "Zypher-Master-Key-X7pQ9r2s"

/* Access extension globals */
#ifdef ZTS
#define ZYPHER_G(v) ZEND_TSRMG(zypher_globals_id, zend_zypher_globals *, v)
#else
#define ZYPHER_G(v) (zypher_globals.v)
#endif

/* Function declarations */
zend_op_array *zypher_compile_file(zend_file_handle *file_handle, int type);

#endif /* PHP_ZYPHER_H */