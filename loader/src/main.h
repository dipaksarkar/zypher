/**
 * Main header file for Zypher PHP Extension
 */
#ifndef ZYPHER_MAIN_H
#define ZYPHER_MAIN_H

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "Zend/zend_extensions.h" // Add Zend extension headers
#include "src/php_loader.h"

/* Function declarations for module init, shutdown, and info */
PHP_MINIT_FUNCTION(zypher);
PHP_MSHUTDOWN_FUNCTION(zypher);
PHP_MINFO_FUNCTION(zypher);

/* Zend extension declarations */
static int zypher_startup(zend_extension *extension);
static void zypher_shutdown(zend_extension *extension);

/* Original zend compile file function */
extern zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);

/* Custom compile file handler */
zend_op_array *zypher_compile_file(zend_file_handle *file_handle, int type);

#endif /* ZYPHER_MAIN_H */