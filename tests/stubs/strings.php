<?php

/**
 * String handling test file
 * Tests string operations and manipulations
 * Perfect for testing string encryption features
 */

// String variables with different quoting styles
$singleQuoted = 'This is a single-quoted string';
$doubleQuoted = "This is a double-quoted string";
$heredoc = <<<EOD
This is a heredoc string
spanning multiple lines
with variables like $doubleQuoted
EOD;

$nowdoc = <<<'EOD'
This is a nowdoc string
spanning multiple lines
but not parsing variables like $doubleQuoted
EOD;

// String with special characters
$specialChars = "Special chars: \n new line \t tab \\ backslash";
$unicodeString = "Unicode characters: 你好, こんにちは, مرحبا";

// Very long string to test encoding overhead
$longString = str_repeat("This is a very long string that will be repeated multiple times to test encoding performance with long strings. ", 20);

// String functions
$str = "The quick brown fox jumps over the lazy dog";
$length = strlen($str);
$words = explode(" ", $str);
$substring = substr($str, 4, 5); // "quick"
$position = strpos($str, "fox");
$replaced = str_replace("fox", "cat", $str);
$uppercase = strtoupper($str);
$lowercase = strtolower($str);
$reversed = strrev($str);
$trimmed = trim("  spaces around  ");
$padded = str_pad("Padded", 10, "-", STR_PAD_BOTH);

// String concatenation
$concat1 = "Hello " . "World";
$concat2 = "Hello " . 123;
$concat3 = "Value: " . true;

// String interpolation
$name = "Alice";
$age = 30;
$interpolated = "My name is $name and I am $age years old";
$complex = "This {$name}'s age is {$age}";

// Regular expressions
$pattern = '/[a-z]+/i';
preg_match($pattern, "Testing123", $matches);
$regexMatches = $matches[0]; // "Testing"

$replacePattern = '/(\w+)@(\w+)\.(\w+)/';
$email = "user@example.com";
$regexReplaced = preg_replace($replacePattern, "$1 AT $2 DOT $3", $email);

// Base64 encoding/decoding
$original = "Original string for base64";
$base64 = base64_encode($original);
$decoded = base64_decode($base64);

// HTML special chars
$html = "<p>This is a paragraph with <b>bold</b> text</p>";
$escaped = htmlspecialchars($html);

// String to array and back
$csvString = "apple,banana,cherry,date";
$csvArray = explode(",", $csvString);
$csvJoined = implode("|", $csvArray);

// Output results
echo "Single quoted: $singleQuoted\n";
echo "Double quoted: $doubleQuoted\n";
echo "Heredoc: $heredoc\n";
echo "Nowdoc: $nowdoc\n";
echo "Special chars: $specialChars\n";
echo "Unicode: $unicodeString\n";
echo "Long string (excerpt): " . substr($longString, 0, 50) . "...\n";
echo "String length: $length\n";
echo "Substring: $substring\n";
echo "Replaced: $replaced\n";
echo "Uppercase: $uppercase\n";
echo "Lowercase: $lowercase\n";
echo "Concat: $concat1, $concat2, $concat3\n";
echo "Interpolated: $interpolated\n";
echo "Complex interpolation: $complex\n";
echo "Regex matches: $regexMatches\n";
echo "Regex replaced: $regexReplaced\n";
echo "Base64: $base64\n";
echo "Escaped HTML: $escaped\n";
echo "CSV joined: $csvJoined\n";

// Return a collection of results for testing
return [
    'status' => 'success',
    'message' => 'String manipulation test completed',
    'results' => [
        'singleQuoted' => $singleQuoted,
        'doubleQuoted' => $doubleQuoted,
        'heredoc' => $heredoc,
        'nowdoc' => $nowdoc,
        'longStringLength' => strlen($longString),
        'base64' => $base64,
        'regexResults' => $regexMatches
    ]
];
