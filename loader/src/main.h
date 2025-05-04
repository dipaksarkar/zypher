/**
 * Main header file for Zypher PHP Extension
 */
#ifndef ZYPHER_MAIN_H
#define ZYPHER_MAIN_H

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "src/php_loader.h"

/* Function declarations for module init, shutdown, and info */
PHP_MINIT_FUNCTION(zypher);
PHP_MSHUTDOWN_FUNCTION(zypher);
PHP_MINFO_FUNCTION(zypher);

/* Original zend compile file function */
extern zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);

/* Custom compile file handler */
zend_op_array *zypher_compile_file(zend_file_handle *file_handle, int type);

/* Define debug macro */
#undef DEBUG
#define DEBUG (ZYPHER_G(debug_mode) && php_get_module_initialized())

#endif /* ZYPHER_MAIN_H */