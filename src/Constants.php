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
     * Current version of Zypher
     */
    const VERSION = '2.0.0';

    /**
     * Format version of encoded files
     */
    const FORMAT_VERSION = 2;

    /**
     * Format type for source code encoding
     */
    const FORMAT_SOURCE = 1;

    /**
     * Format type for opcode encoding
     */
    const FORMAT_OPCODE = 2;

    /**
     * Get the current version
     * 
     * @return string The current version
     */
    public static function getVersion(): string
    {
        return self::VERSION;
    }

    /**
     * Get the master key from the environment or fall back to a default
     * WARNING: The default should never be used in production
     * 
     * @return string The master key to use for encryption
     */
    public static function getMasterKey(): string
    {
        return 'Zypher-Master-Key-X7pQ9r2s';
    }

    /**
     * Get the signature that marks files as Zypher-encoded
     * Using a method instead of a constant to avoid false-positives
     * when searching for encoded files
     * 
     * @return string The signature used to identify encoded files
     */
    public static function getSignature(): string
    {
        return 'Z' . 'Y' . 'P' . 'H' . '0' . '2';
    }
}
