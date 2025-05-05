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

        // Apply PHP tag handling for string encryption if needed
        if ($options['string_encryption']) {
            $obfuscatedCode = "<?php\n";
            $phpOpenTagAdded = true;

            // Check if zypher_decode_string exists
            $obfuscatedCode .= "if (!function_exists('zypher_decode_string')) {\n";
            $obfuscatedCode .= "    trigger_error('Zypher extension missing or outdated - string decoding function not available', E_USER_ERROR);\n";
            $obfuscatedCode .= "}\n\n";

            // If there's a PHP opening tag in the original code, remove it to avoid duplication
            if (strpos($code, '<?php') === 0) {
                $code = substr($code, 5);
            }
        } else if (strpos($code, '<?php') === 0) {
            $obfuscatedCode = "<?php";
            $phpOpenTagAdded = true;
            $code = substr($code, 5);
        }

        // Second pass: Replace variable names with obfuscated versions
        $currentScope = "global";
        $scopeStack = [];
        $braceLevel = 0;
        $inFunction = false;
        $inClass = false;

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
                // Handle PHP open tags if not already added
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
            // Create a unique junk code instance
            $junk = $this->generateJunkCode();

            // Make sure we have a PHP tag at the beginning
            if (!$phpOpenTagAdded) {
                $obfuscatedCode = "<?php\n" . $junk . "\n" . $obfuscatedCode;
            } else {
                // Find the position after PHP tag
                $pos = strpos($obfuscatedCode, "<?php") + 5;
                // Insert junk after PHP tag
                $obfuscatedCode = substr($obfuscatedCode, 0, $pos) . "\n" . $junk . "\n" . substr($obfuscatedCode, $pos);
            }

            // Insert junk at various positions but avoid inserting in the middle of code structures
            $codeLines = explode("\n", $obfuscatedCode);
            $resultLines = [];
            foreach ($codeLines as $i => $line) {
                $resultLines[] = $line;
                // Add junk every 10 lines, but only if the line ends with a semicolon or brace
                if ($i > 0 && $i % 10 === 0 && (substr(trim($line), -1) === ';' || substr(trim($line), -1) === '}')) {
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

        // Use the native extension function to decode string at runtime
        return 'zypher_decode_string("' . $hex . '", "' . md5($key) . '")';
    }

    /**
     * Generate meaningless code that will be eliminated by the optimizer
     * 
     * @return string A piece of junk code
     */
    public function generateJunkCode()
    {
        $junkFunctions = [
            'if(false){$_x=array();foreach($_x as $k=>$v){echo $k;}}',
            '$_t=microtime();if(false&&$_t){eval("return false;");}',
            'function _z' . mt_rand() . '(){return false;} /* junk function */',
            '$_a=array();$_a[]=1;$_a[]=2;if(count($_a)>999){$_a=array_reverse($_a);}',
        ];

        return $junkFunctions[array_rand($junkFunctions)];
    }
}
