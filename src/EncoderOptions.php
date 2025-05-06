<?php

namespace Zypher;

use Zypher\Constants;

/**
 * EncoderOptions class
 * 
 * Handles options for the Zypher PHP Encoder
 * 
 * @package Zypher
 */

/**
 * Class to hold encoder options with proper defaults
 */
class EncoderOptions
{
    /**
     * @var string Master key used for encryption
     */
    public $masterKey = 'Zypher-Master-Key-X7pQ9r2s';

    /**
     * @var bool Whether to show verbose output and debug information
     */
    public $verboseMode = false;

    /**
     * @var array Obfuscation options
     */
    public $obfuscation = [
        'enabled' => false,
        'shuffle_statements' => false,
        'junk_code' => false,
        'string_encryption' => false,
    ];

    /**
     * @var array Opcode compilation options
     */
    public $opcodes = [
        'enabled' => true,      // Default to using opcodes
        'format_version' => Constants::FORMAT_VERSION,
        'format_type' => Constants::FORMAT_OPCODE
    ];

    /**
     * @var array Patterns for files to exclude
     */
    public $excludePatterns = [];

    /**
     * Constructor to initialize options from command-line arguments
     * 
     * @param array $args Command line arguments
     */
    public function __construct(array $args = [])
    {
        // Set default master key
        $this->masterKey = Constants::getMasterKey();

        // Start from the third argument (after script name and source path)
        for ($i = 2; $i < count($args); $i++) {
            if (substr($args[$i], 0, 12) === '--master-key=') {
                $this->masterKey = substr($args[$i], 12);
            } elseif (substr($args[$i], 0, 10) === '--exclude=') {
                $patterns = substr($args[$i], 10);
                $this->excludePatterns = explode(',', $patterns);
            } elseif ($args[$i] === '--verbose') {
                $this->verboseMode = true;
            } elseif ($args[$i] === '--obfuscate') {
                $this->obfuscation['enabled'] = true;
            } elseif ($args[$i] === '--shuffle-stmts') {
                $this->obfuscation['shuffle_statements'] = true;
                $this->obfuscation['enabled'] = true; // Auto-enable obfuscation
            } elseif ($args[$i] === '--junk-code') {
                $this->obfuscation['junk_code'] = true;
                $this->obfuscation['enabled'] = true; // Auto-enable obfuscation
            } elseif ($args[$i] === '--string-encryption') {
                $this->obfuscation['string_encryption'] = true;
                $this->obfuscation['enabled'] = true; // Auto-enable obfuscation
            } elseif ($args[$i] === '--no-opcodes') {
                $this->opcodes['enabled'] = false;
                $this->opcodes['format_type'] = Constants::FORMAT_SOURCE;
            } elseif ($args[$i] === '--opcodes') {
                $this->opcodes['enabled'] = true;
                $this->opcodes['format_type'] = Constants::FORMAT_OPCODE;
            }
        }
    }
}
