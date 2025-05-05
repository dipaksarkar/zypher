#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "Zend/zend_hash.h"

#include "src/php_loader.h"
#include "security.h"

#include <time.h>

/* Declare external reference to zypher_globals */
#ifdef ZTS
ZEND_TSRMLS_CACHE_EXTERN()
#else
extern zend_zypher_globals zypher_globals;
#endif

/* Check for debugging tools */
int zypher_check_debugger(void)
{
    if (!ZYPHER_G(debugger_protection))
    {
        if (DEBUG)
            php_printf("DEBUG: Debugger protection is disabled\n");
        return 0; // Protection disabled
    }

#ifdef ZEND_DEBUG
    if (DEBUG)
        php_printf("DEBUG: Running in debug build\n");
    return 1; // Running in debug build
#endif

    // Check for common debuggers
    if (zend_hash_str_exists(&module_registry, "xdebug", sizeof("xdebug") - 1))
    {
        if (DEBUG)
            php_printf("DEBUG: Xdebug module detected\n");
        return 1;
    }

    // Check for assertion being active
    zend_string *key = zend_string_init("assert.active", sizeof("assert.active") - 1, 0);
    zval *value = zend_hash_find(EG(ini_directives), key);
    zend_string_release(key);

    if (value && Z_TYPE_P(value) == IS_STRING &&
        Z_STRLEN_P(value) == 1 && Z_STRVAL_P(value)[0] == '1')
    {
        if (DEBUG)
            php_printf("DEBUG: PHP assertions are active\n");
        return 1;
    }

    if (DEBUG)
        php_printf("DEBUG: No debugger detected\n");
    return 0;
}

/* Verify license (domain and expiry) */
int zypher_verify_license(const char *domain, time_t timestamp)
{
    // Check expiry if set
    if (ZYPHER_G(license_expiry) > 0 && time(NULL) > ZYPHER_G(license_expiry))
    {
        if (DEBUG)
            php_printf("DEBUG: License expired (current: %ld, expiry: %ld)\n",
                       (long)time(NULL), (long)ZYPHER_G(license_expiry));
        return ZYPHER_ERR_EXPIRED;
    }

    // Check domain if set
    if (ZYPHER_G(license_domain) && *ZYPHER_G(license_domain))
    {
        char *server_name = NULL;

        // Try to get server name
        zval *server_zval;
        zval *server_name_zval;

        // Check if _SERVER is available
        if ((server_zval = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1)) != NULL &&
            Z_TYPE_P(server_zval) == IS_ARRAY &&
            (server_name_zval = zend_hash_str_find(Z_ARRVAL_P(server_zval), "SERVER_NAME", sizeof("SERVER_NAME") - 1)) != NULL)
        {
            // Convert to string if needed
            zval tmp_zval;
            if (Z_TYPE_P(server_name_zval) != IS_STRING)
            {
                tmp_zval = *server_name_zval;
                zval_copy_ctor(&tmp_zval);
                convert_to_string(&tmp_zval);
                server_name = Z_STRVAL(tmp_zval);
            }
            else
            {
                server_name = Z_STRVAL_P(server_name_zval);
            }

            // Compare domain
            if (server_name && strcmp(server_name, ZYPHER_G(license_domain)) != 0)
            {
                if (DEBUG)
                    php_printf("DEBUG: Domain mismatch (current: %s, licensed: %s)\n",
                               server_name, ZYPHER_G(license_domain));
                // Domain mismatch
                return ZYPHER_ERR_DOMAIN;
            }

            if (DEBUG)
                php_printf("DEBUG: Domain validation passed: %s\n", server_name);
        }
        else if (DEBUG)
        {
            php_printf("DEBUG: _SERVER or SERVER_NAME not available for domain verification\n");
        }
    }

    return ZYPHER_ERR_NONE;
}