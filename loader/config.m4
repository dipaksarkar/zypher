PHP_ARG_ENABLE([zypher],
  [whether to enable Zypher extension],
  [AS_HELP_STRING([--enable-zypher],
    [Enable Zypher support])],
  [no])

PHP_ARG_WITH([openssl],
  [for OpenSSL support],
  [AS_HELP_STRING([--with-openssl],
    [Include OpenSSL support])],
  [yes])

PHP_ARG_WITH([debug],
  [for zypher debug support],
  [AS_HELP_STRING([--with-debug],
    [Enable Zypher debug mode])],
  [no],
  [no])

if test "$PHP_ZYPHER" != "no"; then
  # Check for OpenSSL support
  if test "$PHP_OPENSSL" != "no"; then
    AC_MSG_CHECKING(for OpenSSL)
    
    for i in $PHP_OPENSSL /usr/local /usr; do
      if test -r $i/include/openssl/evp.h; then
        OPENSSL_DIR=$i
        AC_MSG_RESULT(found in $i)
        break
      fi
    done
    
    if test -z "$OPENSSL_DIR"; then
      AC_MSG_RESULT(not found)
      AC_MSG_ERROR(Please reinstall OpenSSL)
    fi

    PHP_ADD_INCLUDE($OPENSSL_DIR/include)
    PHP_ADD_LIBRARY_WITH_PATH(ssl, $OPENSSL_DIR/$PHP_LIBDIR, ZYPHER_SHARED_LIBADD)
    PHP_ADD_LIBRARY_WITH_PATH(crypto, $OPENSSL_DIR/$PHP_LIBDIR, ZYPHER_SHARED_LIBADD)
  fi

  # Enable debug mode if requested
  if test "$PHP_DEBUG" = "yes" || test "$PHP_WITH_DEBUG" = "yes"; then
    AC_DEFINE([ENABLE_ZYPHER_DEBUG], 1, [Whether to enable Zypher debug mode])
    # Remove optimize flags and add -g for better debugging
    CFLAGS=`echo "$CFLAGS" | sed -e 's/-O[0-9s]//g'`
    CFLAGS="$CFLAGS -g -O0"
  fi

  # Define source files
  ZYPHER_SOURCES="src/main.c src/decrypt.c src/security.c src/utils.c"

  PHP_SUBST(ZYPHER_SHARED_LIBADD)
  PHP_NEW_EXTENSION(zypher, $ZYPHER_SOURCES, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
  PHP_INSTALL_HEADERS([ext/zypher], [src/php_loader.h src/main.h src/decrypt.h src/security.h src/utils.h])
fi