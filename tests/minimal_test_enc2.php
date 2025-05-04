<?php
// Zypher encoded file wrapper
// This wrapper ensures the Zypher extension is loaded before processing the encoded file
if(!extension_loaded('zypher')){
    echo "\nScript error: the Zypher Loader for PHP needs to be installed.\n";
    echo "The Zypher Loader is the industry standard PHP extension for running protected PHP code,\n";
    echo "and can usually be added easily to a PHP installation.\n";
    exit(199);
}

// The encoded file will be processed by the Zypher extension
include(__DIR__ . '/' . basename('tests/minimal_test_enc2'));