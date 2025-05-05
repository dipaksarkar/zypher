<?php

namespace Zypher;

/**
 * Constants for the Zypher PHP Encoder
 * 
 * This file contains all constants used by the encoder components
 * 
 * @package Zypher
 */

class Constants
{
    /**
     * Get the master key from the environment or fall back to a default
     * WARNING: The default should never be used in production
     * 
     * @return string The master key to use for encryption
     */
    public static function getMasterKey(): string
    {
        return getenv('ZYPHER_MASTER_KEY') ?: 'Zypher-Master-Key-X7pQ9r2s';
    }

    /**
     * Signature that marks files as Zypher-encoded
     */
    const SIGNATURE = 'ZYPH01';

    /**
     * Debug mode - Set to false for real AES encryption, true for base64 encoding (testing)
     */
    const DEBUG = false;
}
