<?php

namespace Zypher;

/**
 * Obfuscator class
 * 
 * Handles code transformation and obfuscation for the Zypher PHP Encoder
 * 
 * @package Zypher
 */

/**
 * Obfuscator class to handle code transformations
 */
class Obfuscator
{
    /**
     * @var array Special variables that should not be renamed
     */
    private $skipVars = [
        '$this',
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_SESSION',
        '$_COOKIE',
        '$_SERVER',
        '$_FILES',
        '$_ENV',
        '$GLOBALS',
        '$argv',
        '$argc'
    ];

    /**
     * Transform PHP code by obfuscating variable names, adding junk code, etc.
     *
     * @param string $code PHP source code
     * @param array $options Obfuscation options
     * @return string Obfuscated PHP code
     */
    public function obfuscateCode($code, $options)
    {
        // Only proceed if we have tokenizer extension
        if (!extension_loaded('tokenizer')) {
            echo "Warning: Tokenizer extension not available, skipping code obfuscation\n";
            return $code;
        }

        // Parse PHP tokens
        $tokens = token_get_all($code);
        $obfuscatedCode = '';
        $phpOpenTagAdded = false;
        $inPhp = false; // To track if we're inside PHP code section

        // Variables to track scope and names
        $variables = [];
        $obfuscatedMap = [];
        $braceLevel = 0;

        // First pass: Identify variables
        $inFunction = false;
        $inClass = false;
        $currentScope = "global";
        $scopeStack = [];

        // Process each token to identify variables in their proper scope
        foreach ($tokens as $i => $token) {
            if (is_array($token)) {
                $tokenType = $token[0];
                $tokenValue = $token[1];

                // Track scope changes
                if ($tokenType === T_FUNCTION) {
                    $inFunction = true;
                    // Look ahead to find function name
                    $j = $i + 1;
                    while ($j < count($tokens) && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                        $j++;
                    }
                    $functionName = is_array($tokens[$j]) && $tokens[$j][0] === T_STRING ? $tokens[$j][1] : 'anonymous';
                    array_push($scopeStack, $currentScope);
                    $currentScope = "function:" . $functionName;
                } else if ($tokenType === T_CLASS) {
                    $inClass = true;
                    // Look ahead to find class name
                    $j = $i + 1;
                    while ($j < count($tokens) && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                        $j++;
                    }
                    $className = is_array($tokens[$j]) && $tokens[$j][0] === T_STRING ? $tokens[$j][1] : 'anonymous';
                    array_push($scopeStack, $currentScope);
                    $currentScope = "class:" . $className;
                } else if ($tokenType === T_VARIABLE) {
                    // Skip special variables
                    if (!in_array($tokenValue, $this->skipVars)) {
                        // Record variable with its scope
                        $variables[$currentScope][$tokenValue] = true;
                    }
                }
            } else {
                // Non-array tokens are typically single characters like { } ; etc.
                if ($token === '{') {
                    $braceLevel++;
                } else if ($token === '}') {
                    $braceLevel--;
                    if ($braceLevel === 0 && ($inFunction || $inClass)) {
                        if (!empty($scopeStack)) {
                            $currentScope = array_pop($scopeStack);
                        } else {
                            $currentScope = "global";
                        }
                        $inFunction = false;
                        $inClass = false;
                    }
                }
            }
        }

        // Create obfuscated names for each variable in each scope
        foreach ($variables as $scope => $vars) {
            foreach ($vars as $var => $dummy) {
                // Generate a unique obfuscated name for this scope+variable
                $obfuscatedMap[$scope][$var] = '$' . '_z' . substr(md5($var . $scope . mt_rand()), 0, 8);
            }
        }

        // Make sure we strip any existing PHP open tags from the input code
        // to avoid duplication when we add our own
        $hasPhpOpenTag = false;
        $codeWithoutOpenTag = $code;

        if (strpos(trim($code), '<?php') === 0) {
            // Strip the PHP open tag
            $codeWithoutOpenTag = substr($code, 5);
            $hasPhpOpenTag = true;
        }

        // Apply PHP tag handling for string encryption if needed
        if ($options['string_encryption']) {
            $obfuscatedCode = "<?php\n";
            $phpOpenTagAdded = true;

            // Check if zypher_decode_string exists - using double quotes to avoid escaping issues
            $obfuscatedCode .= "if (!function_exists(\"zypher_decode_string\")) {\n";
            $obfuscatedCode .= "    trigger_error(\"Zypher extension missing or outdated - string decoding function not available\", E_USER_ERROR);\n";
            $obfuscatedCode .= "}\n\n";

            // Use the code without the PHP open tag to avoid duplication
            $code = $codeWithoutOpenTag;
        } else if ($hasPhpOpenTag) {
            $obfuscatedCode = "<?php";
            $phpOpenTagAdded = true;
            $code = $codeWithoutOpenTag;
        }

        // Second pass: Replace variable names with obfuscated versions
        $currentScope = "global";
        $scopeStack = [];
        $braceLevel = 0;
        $inFunction = false;
        $inClass = false;

        // Re-tokenize the code without PHP open tag if it was removed
        if ($hasPhpOpenTag) {
            $tokens = token_get_all($code);
        }

        for ($i = 0; $i < count($tokens); $i++) {
            $token = $tokens[$i];

            if (is_array($token)) {
                $tokenType = $token[0];
                $tokenValue = $token[1];

                // Track scope changes for correct variable replacement
                if ($tokenType === T_FUNCTION) {
                    $inFunction = true;
                    // Look ahead to find function name
                    $j = $i + 1;
                    while ($j < count($tokens) && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                        $j++;
                    }
                    $functionName = is_array($tokens[$j]) && $tokens[$j][0] === T_STRING ? $tokens[$j][1] : 'anonymous';
                    array_push($scopeStack, $currentScope);
                    $currentScope = "function:" . $functionName;
                    $obfuscatedCode .= $tokenValue;
                } else if ($tokenType === T_CLASS) {
                    $inClass = true;
                    // Look ahead to find class name
                    $j = $i + 1;
                    while ($j < count($tokens) && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                        $j++;
                    }
                    $className = is_array($tokens[$j]) && $tokens[$j][0] === T_STRING ? $tokens[$j][1] : 'anonymous';
                    array_push($scopeStack, $currentScope);
                    $currentScope = "class:" . $className;
                    $obfuscatedCode .= $tokenValue;
                }
                // Skip PHP open tags entirely since we've already added our own
                else if ($tokenType === T_OPEN_TAG && $phpOpenTagAdded) {
                    // Skip this token - we already added the PHP open tag
                    continue;
                }
                // Add PHP open tag if not already added
                else if ($tokenType === T_OPEN_TAG && !$phpOpenTagAdded) {
                    $obfuscatedCode .= $tokenValue;
                    $phpOpenTagAdded = true;
                }
                // Replace variable names with obfuscated versions
                else if ($tokenType === T_VARIABLE) {
                    // Check if this is a property access like $this->property
                    $skipReplacement = false;
                    if ($i >= 2 && is_array($tokens[$i - 1]) && $tokens[$i - 1][0] === T_OBJECT_OPERATOR) {
                        $skipReplacement = true;
                    }

                    // Skip special variables
                    if (in_array($tokenValue, $this->skipVars) || $skipReplacement) {
                        $obfuscatedCode .= $tokenValue;
                    }
                    // Replace with obfuscated name if it exists in this scope
                    else if (isset($obfuscatedMap[$currentScope][$tokenValue])) {
                        $obfuscatedCode .= $obfuscatedMap[$currentScope][$tokenValue];
                    }
                    // Fall back to global scope if not found in current scope
                    else if (isset($obfuscatedMap["global"][$tokenValue])) {
                        $obfuscatedCode .= $obfuscatedMap["global"][$tokenValue];
                    }
                    // If no mapping found, keep original
                    else {
                        $obfuscatedCode .= $tokenValue;
                    }
                }
                // Optionally encrypt strings
                else if ($options['string_encryption'] && $tokenType === T_CONSTANT_ENCAPSED_STRING) {
                    // Remove quotes
                    $str = substr($tokenValue, 1, -1);
                    // Only encrypt strings above certain length to avoid overhead
                    if (strlen($str) > 3 && !preg_match('/^[0-9.]+$/', $str)) {
                        $obfuscatedCode .= $this->obfuscateString($str, 'zypher-key');
                    } else {
                        $obfuscatedCode .= $tokenValue;
                    }
                } else {
                    $obfuscatedCode .= $tokenValue;
                }
            } else {
                // Handle braces to track scope levels
                if ($token === '{') {
                    $braceLevel++;
                    $obfuscatedCode .= $token;
                } else if ($token === '}') {
                    $braceLevel--;
                    $obfuscatedCode .= $token;

                    if ($braceLevel === 0 && ($inFunction || $inClass)) {
                        if (!empty($scopeStack)) {
                            $currentScope = array_pop($scopeStack);
                        } else {
                            $currentScope = "global";
                        }
                        $inFunction = false;
                        $inClass = false;
                    }
                } else {
                    $obfuscatedCode .= $token;
                }
            }
        }

        // Add junk code if option enabled
        if ($options['junk_code']) {
            // Create a unique junk code instance for the beginning of the file
            $junk = $this->generateJunkCode();

            // Make sure we have a PHP tag at the beginning
            if (!$phpOpenTagAdded) {
                $obfuscatedCode = "<?php\n" . $junk . "\n" . $obfuscatedCode;
            } else {
                // Find the position after PHP tag, and skip whitespace
                $pos = strpos($obfuscatedCode, "<?php") + 5;

                // For safety, add the junk code in a separate line after the PHP opening tag
                // and before any actual code
                $obfuscatedCode = substr($obfuscatedCode, 0, $pos) . "\n" . $junk . substr($obfuscatedCode, $pos);
            }

            // For safety, we'll only add additional junk code at the global scope
            // to avoid affecting class or function behavior
            $lines = explode("\n", $obfuscatedCode);
            $resultLines = [];
            $braceLevel = 0;
            $inPhpCode = false;

            foreach ($lines as $i => $line) {
                $resultLines[] = $line;

                // Count braces to track scope
                $trimmedLine = trim($line);
                if (strpos($trimmedLine, '<?php') !== false) {
                    $inPhpCode = true;
                }

                // Only proceed if we're in PHP code
                if (!$inPhpCode) {
                    continue;
                }

                // Count opening and closing braces to track nesting level
                $braceLevel += substr_count($trimmedLine, '{');
                $braceLevel -= substr_count($trimmedLine, '}');

                // Only insert junk at global scope (braceLevel = 0) and only after specific lines
                // that are more likely to be safe insertion points
                if (
                    $i > 0 && $i % 10 === 0 && $braceLevel === 0 &&
                    (substr($trimmedLine, -1) === ';' || substr($trimmedLine, -1) === '}') &&
                    strpos($trimmedLine, 'namespace') === false &&
                    strpos($trimmedLine, 'use ') === false
                ) {
                    $resultLines[] = $this->generateJunkCode();
                }
            }
            $obfuscatedCode = implode("\n", $resultLines);
        }

        return $obfuscatedCode;
    }

    /**
     * String encryption function to obfuscate string literals in the code
     * 
     * @param string $str The string to encrypt
     * @param string $key Encryption key
     * @return string PHP function call that will decode the string using the native extension
     */
    public function obfuscateString($str, $key)
    {
        // XOR encryption with rotating key
        $result = '';
        $keyLen = strlen($key);
        for ($i = 0; $i < strlen($str); $i++) {
            $result .= chr(ord($str[$i]) ^ ord($key[$i % $keyLen]));
        }

        // Convert to hex representation
        $hex = bin2hex($result);

        // Ensure quotes are properly escaped to prevent syntax errors
        $escaped_hex = addslashes($hex);
        $escaped_key = addslashes(md5($key));

        // Use the native extension function to decode string at runtime
        return 'zypher_decode_string("' . $escaped_hex . '", "' . $escaped_key . '")';
    }

    /**
     * Generate meaningless code that will be eliminated by the optimizer
     * 
     * @return string A piece of junk code
     */
    public function generateJunkCode()
    {
        // Create an array of junk code snippets that won't affect program output
        // - Wrapped in if(false) to ensure they never execute
        // - No output functions (echo, print, etc.)
        // - No function declarations outside if(false) blocks
        // - No eval() or other potentially dangerous functions
        $junkFunctions = [
            'if(false){$_zx=array();foreach($_zx as $_zk=>$_zv){$_zx[$_zk]=$_zv;}}',
            'if(false){$_zt=microtime();if($_zt){$_zt+=1;}}',
            'if(false){function _zf' . mt_rand(1000, 9999) . '(){return null;}}',
            'if(false){$_za=array();$_za[]=mt_rand(0,1);if(count($_za)>999){$_za=array();}}',
        ];

        return $junkFunctions[array_rand($junkFunctions)];
    }
}
