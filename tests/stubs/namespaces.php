<?php

/**
 * Namespace and autoloading test file
 * Tests namespaces, use statements, and class autoloading
 */

namespace Zypher\Test;

// Define classes in nested namespaces
class Loader
{
    private $name;
    private $isLoaded = false;

    public function __construct($name)
    {
        $this->name = $name;
        echo "Loader created for '$name'\n";
    }

    public function load()
    {
        $this->isLoaded = true;
        echo "Loaded {$this->name}\n";
        return $this;
    }

    public function isLoaded()
    {
        return $this->isLoaded;
    }
}

namespace Zypher\Test\Utils;

class Helper
{
    public static function formatName($name)
    {
        return ">> $name <<";
    }

    public function process($data)
    {
        return array_map('strtoupper', $data);
    }
}

namespace Zypher\Test\Data;

class Repository
{
    private $items = [];

    public function add($key, $value)
    {
        $this->items[$key] = $value;
        return $this;
    }

    public function get($key)
    {
        return isset($this->items[$key]) ? $this->items[$key] : null;
    }

    public function getAll()
    {
        return $this->items;
    }
}

interface DataProvider
{
    public function getData();
}

trait LoggingCapability
{
    private $logs = [];

    public function log($message)
    {
        $this->logs[] = date('Y-m-d H:i:s') . ": $message";
    }

    public function getLogs()
    {
        return $this->logs;
    }
}

namespace Zypher\Test\Data\Storage;

class FileStorage implements \Zypher\Test\Data\DataProvider
{
    use \Zypher\Test\Data\LoggingCapability;

    private $path;

    public function __construct($path)
    {
        $this->path = $path;
        $this->log("FileStorage initialized with path: $path");
    }

    public function getData()
    {
        $this->log("Retrieving data from path: {$this->path}");
        return [
            'path' => $this->path,
            'type' => 'file',
            'timestamp' => time()
        ];
    }
}

// Main execution namespace
namespace Zypher\Test\App;

// Import classes from other namespaces
use Zypher\Test\Loader;
use Zypher\Test\Utils\Helper;
use Zypher\Test\Data\Repository;
use Zypher\Test\Data\Storage\FileStorage;

// Class with imported namespace dependencies
class Application
{
    private $loader;
    private $helper;
    private $repository;
    private $storage;

    public function __construct()
    {
        $this->loader = new Loader('ApplicationCore');
        $this->helper = new Helper();
        $this->repository = new Repository();
        $this->storage = new FileStorage('/tmp/data');

        echo "Application initialized\n";
    }

    public function run()
    {
        // Load application
        $this->loader->load();

        // Use helper
        $formattedName = Helper::formatName('TestApp');
        echo "Application name: $formattedName\n";

        // Store data
        $this->repository->add('config', [
            'debug' => true,
            'environment' => 'testing',
            'version' => '1.0.0'
        ]);

        // Process data
        $items = ['apple', 'banana', 'cherry'];
        $processed = $this->helper->process($items);
        $this->repository->add('items', $processed);

        // Get data from storage
        $fileData = $this->storage->getData();
        $this->repository->add('storage', $fileData);

        echo "Application run completed\n";

        // Show logs from storage
        echo "Storage logs:\n";
        foreach ($this->storage->getLogs() as $log) {
            echo "- $log\n";
        }

        return $this->repository->getAll();
    }
}

// Execute the application
$app = new Application();
$results = $app->run();

echo "\nApplication results:\n";
print_r($results);

// Return results for testing
return [
    'status' => 'success',
    'message' => 'Namespace test completed',
    'results' => $results
];
