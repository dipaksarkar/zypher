/*
  +----------------------------------------------------------------------+
  | Zypher PHP Loader                                                    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2023-2025 Zypher Team                                  |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Zypher Team <info@zypher.com>                                |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "Zend/zend_compile.h"
#include "Zend/zend_execute.h"
#include "Zend/zend_vm.h"
#include "Zend/zend_operators.h"
#include "Zend/zend_constants.h"
#include "Zend/zend_extensions.h"

#include "php_zypher.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <libgen.h> /* For basename() function */

/* Store original compile file function */
zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);

#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#else
/* Define globals instance for non-thread safe build */
ZEND_DECLARE_MODULE_GLOBALS(zypher)
zend_zypher_globals zypher_globals;
#endif

/* Init globals function - moved before its usage */
static void php_zypher_init_globals(zend_zypher_globals *globals)
{
    globals->license_domain = NULL;
    globals->license_expiry = 0;
    globals->self_healing = 0;
    globals->opcode_cache = NULL;
    memset(globals->anti_tamper_hash, 0, sizeof(globals->anti_tamper_hash));
}

/* Add proper arginfo for zypher_decode_string function */
ZEND_BEGIN_ARG_INFO_EX(arginfo_zypher_decode_string, 0, 0, 2)
ZEND_ARG_INFO(0, hex_string)
ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

/* Add function entries with proper arginfo */
static const zend_function_entry zypher_functions[] = {
    PHP_FE(zypher_decode_string, arginfo_zypher_decode_string)
        PHP_FE_END};

/* Module configuration entries */
PHP_INI_BEGIN()
PHP_INI_ENTRY("zypher.license_domain", "", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("zypher.license_expiry", "0", PHP_INI_ALL, NULL)
PHP_INI_END()

/* Module initialization - Implement the required PHP callbacks */
PHP_MINIT_FUNCTION(zypher)
{
#if defined(ZTS) && defined(COMPILE_DL_ZYPHER)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    ZEND_INIT_MODULE_GLOBALS(zypher, php_zypher_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Initialize opcode cache */
    ALLOC_HASHTABLE(ZYPHER_G(opcode_cache));
    zend_hash_init(ZYPHER_G(opcode_cache), 64, NULL, NULL, 0);

    /* Save original compile file function */
    original_compile_file = zend_compile_file;

    /* Replace with our handler */
    zend_compile_file = zypher_compile_file;

    if (DEBUG)
    {
        php_printf("Zypher PHP Loader v%s initialized (Debug mode is %s)\n",
                   PHP_ZYPHER_VERSION,
                   DEBUG ? "ON" : "OFF");
    }

    return SUCCESS;
}

/* Module shutdown */
PHP_MSHUTDOWN_FUNCTION(zypher)
{
    /* Restore original compile file function */
    zend_compile_file = original_compile_file;

    /* Clean up opcode cache */
    if (ZYPHER_G(opcode_cache))
    {
        zend_hash_destroy(ZYPHER_G(opcode_cache));
        FREE_HASHTABLE(ZYPHER_G(opcode_cache));
        ZYPHER_G(opcode_cache) = NULL;
    }

    /* Cleanup OpenSSL */
    EVP_cleanup();
    ERR_free_strings();

    UNREGISTER_INI_ENTRIES();

    return SUCCESS;
}

/* Module info */
PHP_MINFO_FUNCTION(zypher)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "Zypher Support", "enabled");
    php_info_print_table_row(2, "Version", PHP_ZYPHER_VERSION);
    php_info_print_table_row(2, "OpenSSL Support", "enabled");
    php_info_print_table_row(2, "File Format", "encrypted (AES-256-CBC)");
    php_info_print_table_row(2, "Opcode Support", "enabled (v2.0)");
    php_info_print_table_row(2, "Anti-debugging", ZYPHER_DEBUGGER_PROTECTION ? "enabled" : "disabled");
    php_info_print_table_row(2, "Advanced Obfuscation", "enabled");
    php_info_print_table_row(2, "Debug Mode", DEBUG ? "enabled" : "disabled");
    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}

/* Define the module entry */
zend_module_entry zypher_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_ZYPHER_EXTNAME,    /* Extension name */
    zypher_functions,      /* Function entries */
    PHP_MINIT(zypher),     /* Module init */
    PHP_MSHUTDOWN(zypher), /* Module shutdown */
    NULL,                  /* Request init */
    NULL,                  /* Request shutdown */
    PHP_MINFO(zypher),     /* Module info */
    PHP_ZYPHER_VERSION,    /* Version */
    STANDARD_MODULE_PROPERTIES};

/* Add zend extension entry for loading as zend_extension */
#ifndef ZEND_EXT_API
#define ZEND_EXT_API ZEND_DLEXPORT
#endif

/* Zend extension function declarations */
static int zypher_startup(zend_extension *extension)
{
    return zend_startup_module(&zypher_module_entry);
}

static void zypher_shutdown(zend_extension *extension)
{
    /* Nothing to do here, the module shutdown handle will be called */
}

/* Register as a Zend extension */
zend_extension_version_info extension_version_info = {
    ZEND_EXTENSION_API_NO,
    ZEND_EXTENSION_BUILD_ID};

/* Define Zend extension entry */
ZEND_DLEXPORT zend_extension zend_extension_entry = {
    "Zypher PHP Loader",
    PHP_ZYPHER_VERSION,
    "Zypher Team",
    "https://www.zypher.com/",
    "Copyright (c) Zypher",
    zypher_startup,  /* Startup */
    zypher_shutdown, /* Shutdown */
    NULL,            /* Activate */
    NULL,            /* Deactivate */
    NULL,            /* Message handler */
    NULL,            /* Op Array Handler */
    NULL,            /* Statement Handler */
    NULL,            /* Fcall Begin Handler */
    NULL,            /* Fcall End Handler */
    NULL,            /* Op Array Constructor */
    NULL,            /* Op Array Destructor */
    STANDARD_ZEND_EXTENSION_PROPERTIES};

/* Initialize extension */
ZEND_GET_MODULE(zypher)