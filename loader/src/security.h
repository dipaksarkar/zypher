/**
 * Security and license validation functions for Zypher PHP Extension
 */
#ifndef ZYPHER_SECURITY_H
#define ZYPHER_SECURITY_H

#include <time.h>
#include "php.h"
#include "src/php_loader.h"

/* Check for debugging tools */
int zypher_check_debugger(void);

/* Verify license (domain and expiry) */
int zypher_verify_license(const char *domain, time_t timestamp);

/* Enhanced key derivation function using OpenSSL with multiple iterations */
void zypher_derive_key(const char *master_key, const char *filename, char *output_key, int iterations);

#endif /* ZYPHER_SECURITY_H */