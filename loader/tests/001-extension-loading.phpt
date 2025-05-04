--TEST--
Check if Zypher extension is loaded
--SKIPIF--
<?php
// Nothing to skip - we specifically want to test if the extension loads
?>
--FILE--
<?php
echo "Zypher extension is available\n";
var_dump(extension_loaded('zypher'));
?>
--EXPECT--
Zypher extension is available
bool(true)