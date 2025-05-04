--TEST--
Check if zypher extension is loaded
--SKIPIF--
<?php
if (!extension_loaded('zypher')) echo 'skip zypher extension not available';
?>
--FILE--
<?php
echo "zypher extension is available\n";

// Check for module info
ob_start();
phpinfo(INFO_MODULES);
$info = ob_get_clean();

// Check for zypher in a case-insensitive manner
if (stripos($info, 'zypher') !== false) {
    echo "zypher information found in phpinfo\n";
}
?>
--EXPECT--
zypher extension is available
zypher information found in phpinfo