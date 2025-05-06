dnl
dnl $Id$
dnl

PHP_ARG_ENABLE(zypher, whether to enable Zypher support,
[  --enable-zypher         Enable Zypher support])

PHP_ARG_WITH(openssl, for OpenSSL support,
[  --with-openssl[=DIR]    Include OpenSSL support (requires OpenSSL >= 1.0.1)])

if test "$PHP_ZYPHER" != "no"; then
  dnl Better OpenSSL detection, especially for macOS and Homebrew environments
  if test "$PHP_OPENSSL" = "no"; then
    AC_MSG_ERROR([zypher requires OpenSSL library])
  fi

  dnl Try common OpenSSL locations first
  for i in $PHP_OPENSSL /usr/local/opt/openssl /usr/local/opt/openssl@1.1 /usr/local/opt/openssl@3 /usr/local /usr /opt/homebrew/opt/openssl /opt/homebrew/opt/openssl@1.1 /opt/homebrew/opt/openssl@3 /opt/local /usr/local/Cellar/openssl* ; do
    if test -r $i/include/openssl/evp.h; then
      PHP_OPENSSL_DIR=$i
      AC_MSG_RESULT([OpenSSL found in $i])
      break
    fi
  done

  if test -z "$PHP_OPENSSL_DIR"; then
    dnl Try pkg-config as fallback
    PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.0.1], [
      PHP_OPENSSL_DIR=/usr
      PHP_EVAL_LIBLINE($OPENSSL_LIBS, ZYPHER_SHARED_LIBADD)
      PHP_EVAL_INCLINE($OPENSSL_CFLAGS)
    ], [
      AC_MSG_ERROR([OpenSSL library not found. Install openssl-dev/openssl-devel package or specify path with --with-openssl=<DIR>])
    ])
  else
    dnl Standard approach with specific directory
    PHP_ADD_INCLUDE($PHP_OPENSSL_DIR/include)

    if test -d $PHP_OPENSSL_DIR/lib64; then
      PHP_OPENSSL_LIB_DIR=$PHP_OPENSSL_DIR/lib64
    else
      PHP_OPENSSL_LIB_DIR=$PHP_OPENSSL_DIR/lib
    fi

    PHP_ADD_LIBRARY_WITH_PATH(crypto, $PHP_OPENSSL_LIB_DIR, ZYPHER_SHARED_LIBADD)
    PHP_ADD_LIBRARY_WITH_PATH(ssl, $PHP_OPENSSL_LIB_DIR, ZYPHER_SHARED_LIBADD)
  fi

  dnl Check for OpenSSL version 
  PHP_CHECK_LIBRARY(crypto, EVP_CIPHER_CTX_new, 
  [
    AC_DEFINE(HAVE_EVP_CIPHER_CTX_NEW, 1, [Have newer OpenSSL])
  ], [], [])

  PHP_CHECK_LIBRARY(crypto, EVP_PKEY_CTX_new_id,
  [
    AC_DEFINE(HAVE_EVP_PKEY_CTX_NEW_ID, 1, [Have EVP_PKEY_CTX_NEW_ID (OpenSSL >= 1.0.0)])
  ], [], [])
  
  PHP_CHECK_LIBRARY(crypto, EVP_aes_256_gcm, 
  [
    AC_DEFINE(HAVE_EVP_AES_256_GCM, 1, [Have AES-GCM support])
  ], [], [])

  AC_DEFINE(HAVE_OPENSSL, 1, [Have OpenSSL])

  dnl Add option to enable debugging output
  PHP_ARG_ENABLE(zypher-debug, whether to enable Zypher debug mode,
  [  --enable-zypher-debug   Enable Zypher debug output], no, no)

  if test "$PHP_ZYPHER_DEBUG" != "no"; then
    AC_DEFINE(ENABLE_ZYPHER_DEBUG, 1, [Enable Zypher debugging])
  fi
  
  dnl Add directories for building - FIXED PATH to use $ext_builddir
  PHP_ADD_BUILD_DIR($ext_builddir/include)
  
  dnl Create include directory if it doesn't exist
  if ! test -d "$ext_builddir/include"; then
    mkdir -p "$ext_builddir/include"
  fi

  PHP_NEW_EXTENSION(zypher, 
    zypher.c \
    zypher_compile.c \
    zypher_decrypt.c \
    zypher_security.c \
    zypher_utils.c, 
    $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)

  PHP_SUBST(ZYPHER_SHARED_LIBADD)
fi