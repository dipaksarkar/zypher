<?php

/**
 * Test serialization and special PHP features
 * Tests serialization, reflection, and other PHP features that could be affected by encoding
 */

// Define a serializable class
class SerializableTest implements Serializable
{
    private $data;
    private $id;
    public $publicProp;

    public function __construct($id = null, $data = [])
    {
        $this->id = $id ?: uniqid();
        $this->data = $data;
        $this->publicProp = "Public property value";
    }

    public function serialize()
    {
        return serialize([
            'id' => $this->id,
            'data' => $this->data,
            'public' => $this->publicProp
        ]);
    }

    public function unserialize($data)
    {
        $values = unserialize($data);
        $this->id = $values['id'];
        $this->data = $values['data'];
        $this->publicProp = $values['public'];
    }

    public function getId()
    {
        return $this->id;
    }

    public function getData()
    {
        return $this->data;
    }
}

// Class with magic methods
class MagicTest
{
    private $properties = [];

    public function __set($name, $value)
    {
        echo "Setting '$name' to '$value'\n";
        $this->properties[$name] = $value;
    }

    public function __get($name)
    {
        echo "Getting '$name'\n";
        return $this->properties[$name] ?? null;
    }

    public function __isset($name)
    {
        return isset($this->properties[$name]);
    }

    public function __unset($name)
    {
        unset($this->properties[$name]);
    }

    public function __call($name, $arguments)
    {
        echo "Calling method '$name' with " . count($arguments) . " arguments\n";
        return "Result of $name";
    }

    public static function __callStatic($name, $arguments)
    {
        echo "Calling static method '$name' with " . count($arguments) . " arguments\n";
        return "Static result of $name";
    }

    public function __toString()
    {
        return "MagicTest instance with " . count($this->properties) . " properties";
    }

    public function __invoke($param)
    {
        return "Invoked with parameter: $param";
    }
}

// Class for reflection tests
class ReflectionTest
{
    public $publicProp = 'public';
    protected $protectedProp = 'protected';
    private $privateProp = 'private';

    public function publicMethod($param1, $param2 = null)
    {
        return "Public method called with $param1 and $param2";
    }

    protected function protectedMethod()
    {
        return "Protected method called";
    }

    private function privateMethod()
    {
        return "Private method called";
    }
}

// Test PHP built-in serialization
echo "Testing PHP serialization...\n";

// Create test objects
$testObject = new SerializableTest('test-123', ['key1' => 'value1', 'key2' => 'value2']);
$magicObject = new MagicTest();
$magicObject->name = "Test";
$magicObject->value = 42;

// Test simple variable serialization
$testVars = [
    'null' => null,
    'bool' => true,
    'int' => 42,
    'float' => 3.14159,
    'string' => "This is a test string",
    'array' => [1, 2, 3, 'a' => 'b'],
    'object' => $testObject,
    'nested' => [
        'a' => [1, 2, 3],
        'b' => ["test" => "value"],
        'c' => $magicObject
    ]
];

// Serialize and unserialize
$serialized = [];
$unserialized = [];
$jsonEncoded = [];

foreach ($testVars as $key => $value) {
    // Skip resources as they can't be serialized
    if (is_resource($value)) {
        continue;
    }

    try {
        // PHP serialize/unserialize
        $serialized[$key] = serialize($value);
        $unserialized[$key] = unserialize($serialized[$key]);

        // JSON encode/decode where possible
        if ($key !== 'object' && $key !== 'nested') {
            $jsonEncoded[$key] = [
                'encoded' => json_encode($value),
                'decoded' => json_decode(json_encode($value), true)
            ];
        }
    } catch (Exception $e) {
        echo "Error serializing $key: " . $e->getMessage() . "\n";
    }
}

// Test the __sleep and __wakeup magic methods
class SleepTest
{
    public $publicData;
    private $privateData;
    protected $secretKey;

    public function __construct($public, $private, $secret)
    {
        $this->publicData = $public;
        $this->privateData = $private;
        $this->secretKey = $secret;
    }

    public function __sleep()
    {
        echo "__sleep called\n";
        // Only serialize these properties
        return ['publicData', 'secretKey'];
    }

    public function __wakeup()
    {
        echo "__wakeup called\n";
        // Initialize any missing properties
        $this->privateData = "Regenerated after wakeup";
    }

    public function getAllData()
    {
        return [
            'public' => $this->publicData,
            'private' => $this->privateData,
            'secret' => $this->secretKey
        ];
    }
}

$sleepTest = new SleepTest("Public data", "Private data", "Secret key");
$sleepSerialized = serialize($sleepTest);
$sleepUnserialized = unserialize($sleepSerialized);
$sleepData = $sleepUnserialized->getAllData();

// Test reflection API
echo "\nTesting Reflection API...\n";
$reflectionTest = new ReflectionTest();
$reflection = new ReflectionClass($reflectionTest);

$reflectionData = [
    'name' => $reflection->getName(),
    'properties' => [],
    'methods' => []
];

// Get properties
foreach ($reflection->getProperties() as $property) {
    $property->setAccessible(true);
    $reflectionData['properties'][$property->getName()] = [
        'visibility' => $property->isPublic() ? 'public' : ($property->isProtected() ? 'protected' : 'private'),
        'value' => $property->getValue($reflectionTest)
    ];
}

// Get methods
foreach ($reflection->getMethods() as $method) {
    $method->setAccessible(true);
    $reflectionData['methods'][$method->getName()] = [
        'visibility' => $method->isPublic() ? 'public' : ($method->isProtected() ? 'protected' : 'private'),
        'parameters' => []
    ];

    // Get parameters
    foreach ($method->getParameters() as $param) {
        $reflectionData['methods'][$method->getName()]['parameters'][] = [
            'name' => $param->getName(),
            'required' => !$param->isOptional(),
            'default' => $param->isOptional() ? ($param->isDefaultValueAvailable() ? $param->getDefaultValue() : null) : null
        ];
    }
}

// Test calling a private method via reflection
$privateMethod = $reflection->getMethod('privateMethod');
$privateMethod->setAccessible(true);
$privateResult = $privateMethod->invoke($reflectionTest);

// Test magic methods
echo "\nTesting magic methods...\n";
$magicResult = $magicObject->testMethod("param1", "param2");
$magicStaticResult = MagicTest::staticTest("static_param");
$magicProperty = $magicObject->dynamic;
$magicString = (string)$magicObject;
$magicInvoke = $magicObject("invoke parameter");

// Return all test results
return [
    'status' => 'success',
    'message' => 'Serialization test completed',
    'results' => [
        'serialized' => $serialized,
        'json_encoded' => $jsonEncoded,
        'sleep_test' => $sleepData,
        'reflection' => $reflectionData,
        'reflection_private_call' => $privateResult,
        'magic' => [
            'method_call' => $magicResult,
            'static_call' => $magicStaticResult,
            'property_access' => $magicProperty,
            'to_string' => $magicString,
            'invoke' => $magicInvoke
        ]
    ]
];
