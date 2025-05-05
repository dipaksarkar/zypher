<?php

/**
 * Constants for the Zypher PHP Encoder
 * 
 * This file contains all constants used by the encoder components
 * 
 * @package Zypher
 */

// Default master key - Used to encrypt the per-file random key
// WARNING: Should be changed in production
define('ZYPHER_DEFAULT_MASTER_KEY', 'Zypher-Master-Key-X7pQ9r2s');

// Signature that marks files as Zypher-encoded
define('ZYPHER_SIGNATURE', 'ZYPH01');

// Debug mode - Set to false for real AES encryption, true for base64 encoding (testing)
define('ZYPHER_DEBUG', false);
