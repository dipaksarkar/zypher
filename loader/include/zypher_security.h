/**
 * Security functions for Zypher PHP Extension
 */
#ifndef ZYPHER_SECURITY_H
#define ZYPHER_SECURITY_H

#include "php.h"
#include "../../include/zypher_loader.h"
#include "../../include/zypher_common.h"
#include "../../build/zypher_master_key.h"

/* Date formats */
#define DATE_FORMAT "%Y-%m-%d"
#define DATE_FORMAT_LEN 10 /* YYYY-MM-DD */

/* Security check results */
typedef enum
{
    SECURITY_CHECK_PASS = 0,
    SECURITY_CHECK_FAIL_EXPIRED,
    SECURITY_CHECK_FAIL_DOMAIN,
    SECURITY_CHECK_FAIL_DEBUGGER,
    SECURITY_CHECK_FAIL_TAMPERED
} security_check_result;

/* Verify if the encoded file license is valid */
int verify_license(const char *expiry_date, const char *domain_lock);

/* Check if a debugger is attached to the process */
int detect_debugger();

/* Derive a key from the master key and other parameters */
char *derive_file_key(const char *master_key, const char *filename, const char *salt);

/* Check if the current date is before the expiry date */
int check_expiry_date(const char *expiry_date);

/* Check if the current domain matches the domain lock */
int check_domain_lock(const char *domain_lock);

/* Generate HMAC for a given message */
char *generate_hmac(const char *key, size_t key_len, const char *msg, size_t msg_len);

#endif /* ZYPHER_SECURITY_H */