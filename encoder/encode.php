#!/usr/bin/env php
<?php
/**
 * Zypher PHP File Encoder
 * 
 * This tool encodes PHP files into a custom format that can only be 
 * executed with the Zypher PHP extension installed.
 * 
 * Usage: php encode.php <source_path> [output_path] [--master-key=your_master_key] [--quiet] [--verbose]
 *        [--obfuscate] [--shuffle-stmts] [--junk-code] [--string-encryption] [--exclude=pattern1,pattern2]
 * If output_path is not specified, it will use source_path with _encoded suffix
 * <source_path> and [output_path] can be either files or directories
 */

// Load required classes
require_once __DIR__ . '/Constants.php';
require_once __DIR__ . '/EncoderOptions.php';
require_once __DIR__ . '/Obfuscator.php';
require_once __DIR__ . '/ZypherEncoder.php';

// Main execution
if (PHP_SAPI !== 'cli') {
    echo "This script must be run from the command line.\n";
    exit(1);
}

// Check if source file is provided
if ($argc < 2) {
    echo "Error: No source path provided\n";
    echo "Usage: php encode.php <source_path> [output_path] [--master-key=your_master_key] [--quiet] [--verbose]\n";
    echo "       [--obfuscate] [--shuffle-stmts] [--junk-code] [--string-encryption] [--exclude=pattern1,pattern2]\n";
    echo "Where: <source_path> and [output_path] can be either a PHP file or a directory\n";
    exit(1);
}

$source_path = $argv[1];
$output_path = null;

// Get the second argument if it doesn't start with -- (which would make it an option)
if (isset($argv[2]) && substr($argv[2], 0, 2) !== '--') {
    $output_path = $argv[2];
}

// Validate source path
if (!file_exists($source_path)) {
    echo "Error: Source path '$source_path' does not exist\n";
    exit(1);
}

if (!is_readable($source_path)) {
    echo "Error: Source path '$source_path' is not readable\n";
    exit(1);
}

// Determine output path if not specified
if (!$output_path) {
    if (is_dir($source_path)) {
        // Create a parallel directory with _encoded suffix
        $path_parts = pathinfo($source_path);
        $parent_dir = dirname($source_path);
        $dir_name = $path_parts['basename'];
        $output_path = $parent_dir . '/' . $dir_name . '_encoded';
    } else {
        // For a single file, use the same path with _encoded suffix
        $path_parts = pathinfo($source_path);
        $output_path = $path_parts['dirname'] . '/' . $path_parts['filename'] . '_encoded.php';
    }
}

// Initialize options with command line arguments
$options = new EncoderOptions($argv);

// Create encoder instance
$encoder = new ZypherEncoder($options);

if (!$options->quietMode) {
    echo "=== Zypher PHP Encoder ===\n";
    echo "Source: $source_path\n";
    echo "Destination: $output_path\n";

    if (!empty($options->excludePatterns)) {
        echo "Exclude patterns: " . implode(', ', $options->excludePatterns) . "\n";
    }

    if (is_dir($source_path)) {
        echo "Processing directory...\n";
    } else {
        echo "Processing file...\n";
    }
}

// Process the source path
$stats = $encoder->processPath($source_path, $output_path);

if (!$options->quietMode) {
    echo "\n=== Encoding Summary ===\n";
    echo "Files processed: {$stats['processed']}\n";
    echo "Files skipped: {$stats['skipped']}\n";
    echo "Errors: {$stats['errors']}\n";

    if ($stats['processed'] > 0) {
        echo "\nTo run encoded files, make sure the Zypher extension is installed.\n";
    }
}

exit($stats['errors'] > 0 ? 1 : 0);
