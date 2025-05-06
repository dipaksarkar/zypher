/*
  +----------------------------------------------------------------------+
  | Zypher PHP Encoder/Loader                                            |
  +----------------------------------------------------------------------+
  | Copyright (c) 2025 Zypher Team                                       |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Zypher Team <team@zypher.com>                                |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_ZYPHER_H
#define PHP_ZYPHER_H

#include "../build/zypher_master_key.h"
#include "../include/zypher_common.h"

extern zend_module_entry zypher_module_entry;
#define phpext_zypher_ptr &zypher_module_entry

/* Define version only if not already defined elsewhere */
#ifndef PHP_ZYPHER_VERSION
#define PHP_ZYPHER_VERSION "1.0.0"
#endif
#define PHP_ZYPHER_EXTNAME "zypher"

/* Declare the original compile file function as external so it can be accessed by other source files */
extern zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);

/* Declare the zypher_compile_file function so it's available to other parts of the extension */
extern zend_op_array *zypher_compile_file(zend_file_handle *file_handle, int type);

/* Define the extension globals */
ZEND_BEGIN_MODULE_GLOBALS(zypher)
char *license_domain;               /* Licensed domain */
time_t license_expiry;              /* License expiration timestamp */
unsigned char anti_tamper_hash[32]; /* Hash to verify extension integrity */
int self_healing;                   /* Enable self-healing code */
HashTable *opcode_cache;            /* Cache for decoded opcodes */
ZEND_END_MODULE_GLOBALS(zypher)

/* Declare globals for use in other files */
#ifdef ZTS
#define ZYPHER_G(v) ZEND_TSRMG(zypher_globals_id, zend_zypher_globals *, v)
ZEND_TSRMLS_CACHE_EXTERN()
#else
#define ZYPHER_G(v) (zypher_globals.v)
extern ZEND_DECLARE_MODULE_GLOBALS(zypher) extern zend_zypher_globals zypher_globals;
#endif

/* Now include loader.h which depends on the above declarations */
#include "../include/zypher_loader.h"

/* Include the rest after shared declarations */
#include "include/zypher_decrypt.h"
#include "include/zypher_security.h"
#include "include/zypher_utils.h"

/* Always refer to the main include directory for header files */

#endif /* PHP_ZYPHER_H */