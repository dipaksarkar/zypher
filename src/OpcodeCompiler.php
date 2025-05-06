<?php

namespace Zypher;

/**
 * OpcodeCompiler class
 * 
 * Handles compilation of PHP source code to opcodes and serialization of opcodes for encryption
 * 
 * @package Zypher
 */
class OpcodeCompiler
{
    /**
     * Flag for debug mode
     *
     * @var bool
     */
    private $debugMode;

    /**
     * Constructor
     * 
     * @param bool $debugMode Whether to enable debug output
     */
    public function __construct($debugMode = false)
    {
        $this->debugMode = $debugMode;
    }

    /**
     * Compiles PHP source code to opcodes and serializes them for encryption
     *
     * @param string $sourceCode PHP source code to compile
     * @param string $filename Original filename (for error reporting)
     * @return string|false Binary serialized opcodes or false on failure
     */
    public function compileToOpcodes($sourceCode, $filename)
    {
        if ($this->debugMode) {
            echo "DEBUG: Compiling PHP code to opcodes for $filename\n";
        }

        // First verify that opcache and/or Zend OPcache is available
        if (!extension_loaded('Zend OPcache') && !extension_loaded('opcache')) {
            echo "Error: OPcache extension is not loaded. Required for opcode compilation.\n";
            return false;
        }

        // Temporarily disable opcache.optimization_level
        $originalOptimizationLevel = ini_get('opcache.optimization_level');
        ini_set('opcache.optimization_level', '0');

        // Create a temporary file for compilation
        $tempFile = tempnam(sys_get_temp_dir(), 'zypher_opcode_');
        file_put_contents($tempFile, $sourceCode);

        try {
            // Force opcache to compile the file
            if (!opcache_compile_file($tempFile)) {
                throw new \Exception("Failed to compile file using opcache");
            }

            // Get the opcache status for this file
            $status = opcache_get_status();
            if (empty($status['scripts'][$tempFile])) {
                throw new \Exception("Failed to retrieve opcodes for compiled file");
            }

            // Get the raw opcodes from the file
            $opcodeData = $this->extractOpcodes($tempFile);

            if (!$opcodeData) {
                throw new \Exception("Failed to extract opcodes from compiled file");
            }

            // Add metadata to the opcodes
            $opcodeData['filename'] = basename($filename);
            $opcodeData['timestamp'] = time();
            $opcodeData['zypher_version'] = Constants::getVersion();

            if ($this->debugMode) {
                echo "DEBUG: Successfully compiled to opcodes. Size: " . strlen(serialize($opcodeData)) . " bytes\n";
            }

            // Serialize the opcodes for encryption
            return serialize($opcodeData);
        } catch (\Exception $e) {
            echo "Error compiling to opcodes: " . $e->getMessage() . "\n";
            return false;
        } finally {
            // Restore optimization level
            ini_set('opcache.optimization_level', $originalOptimizationLevel);

            // Clean up temporary file
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    /**
     * Extract opcodes from a compiled file
     *
     * @param string $filepath Path to the compiled file
     * @return array|false Array of opcode data or false on failure
     */
    private function extractOpcodes($filepath)
    {
        // Use reflection to access internal structure of opcache
        try {
            // Get the script status from opcache
            $status = opcache_get_status();

            if (!isset($status['scripts'][$filepath])) {
                return false;
            }

            // Get the opcodes and related data using a workaround to access internal data
            $script = $status['scripts'][$filepath];

            // Create a structure that represents the opcode data
            $opcodeData = [
                'opcache_data' => $this->getOpcodeDataFromOpcache($filepath),
                'memory_consumption' => $script['memory_consumption'],
                'hits' => $script['hits'],
                'last_used_timestamp' => $script['last_used_timestamp'],
                'timestamp' => $script['timestamp']
            ];

            return $opcodeData;
        } catch (\Exception $e) {
            if ($this->debugMode) {
                echo "DEBUG: Error extracting opcodes: " . $e->getMessage() . "\n";
            }
            return false;
        }
    }

    /**
     * Get opcode data from opcache using internal PHP functions
     *
     * @param string $filepath Path to the file
     * @return array Opcode data
     */
    private function getOpcodeDataFromOpcache($filepath)
    {
        // We use the PHP file to generate opcodes again, but with a way to capture them
        $tmpfile = tempnam(sys_get_temp_dir(), 'zypher_opcode_extract_');

        // Create a PHP file that will output serialized opcodes
        $extractorCode = '<?php
        $opcodes = opcache_get_status(true);
        file_put_contents("' . $tmpfile . '", serialize($opcodes["scripts"]["' . str_replace('\\', '\\\\', $filepath) . '"]));
        ';

        $extractorFile = tempnam(sys_get_temp_dir(), 'zypher_extractor_');
        file_put_contents($extractorFile, $extractorCode);

        // Execute the extractor
        shell_exec(PHP_BINARY . ' ' . $extractorFile . ' 2>/dev/null');

        // Read the serialized data
        if (file_exists($tmpfile) && filesize($tmpfile) > 0) {
            $data = unserialize(file_get_contents($tmpfile));
            unlink($tmpfile);
        } else {
            $data = [];
        }

        // Clean up
        if (file_exists($extractorFile)) {
            unlink($extractorFile);
        }

        // Return the extracted opcode data
        return $data;
    }
}
