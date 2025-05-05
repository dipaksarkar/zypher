<?php

/**
 * Real-world application example
 * Combines multiple features in a practical application structure
 * Tests all encoding features together
 */

// Configuration
$config = [
    'app_name' => 'Zypher Demo App',
    'version' => '1.0.0',
    'debug' => true,
    'db' => [
        'host' => 'localhost',
        'user' => 'dbuser',
        'pass' => 'secret_password',  // Good candidate for string encryption
        'name' => 'app_database'
    ],
    'api_key' => 'sk_test_abcdefghijklmnopqrstuvwxyz123456', // Secret that needs protection
    'cache_dir' => '/tmp/cache',
    'timezone' => 'UTC'
];

// Set timezone
date_default_timezone_set($config['timezone']);

// Autoloader
spl_autoload_register(function ($className) {
    // Convert namespace to file path
    $path = str_replace('\\', '/', $className) . '.php';
    if (file_exists($path)) {
        require_once $path;
    }
});

// Logger class
class Logger
{
    private static $instance = null;
    private $logFile;
    private $level;

    const LEVEL_DEBUG = 0;
    const LEVEL_INFO = 1;
    const LEVEL_WARNING = 2;
    const LEVEL_ERROR = 3;

    private function __construct($logFile, $level = self::LEVEL_INFO)
    {
        $this->logFile = $logFile;
        $this->level = $level;
        $this->log("Logger initialized", self::LEVEL_DEBUG);
    }

    public static function getInstance($logFile = null, $level = null)
    {
        if (self::$instance === null) {
            self::$instance = new self($logFile ?: 'php://stdout', $level ?: self::LEVEL_INFO);
        }
        return self::$instance;
    }

    public function log($message, $level = self::LEVEL_INFO)
    {
        if ($level >= $this->level) {
            $levelName = $this->getLevelName($level);
            $timestamp = date('Y-m-d H:i:s');
            $logMessage = "[$timestamp] [$levelName] $message\n";

            file_put_contents($this->logFile, $logMessage, FILE_APPEND);
        }
    }

    private function getLevelName($level)
    {
        switch ($level) {
            case self::LEVEL_DEBUG:
                return 'DEBUG';
            case self::LEVEL_INFO:
                return 'INFO';
            case self::LEVEL_WARNING:
                return 'WARNING';
            case self::LEVEL_ERROR:
                return 'ERROR';
            default:
                return 'UNKNOWN';
        }
    }

    public function debug($message)
    {
        $this->log($message, self::LEVEL_DEBUG);
    }

    public function info($message)
    {
        $this->log($message, self::LEVEL_INFO);
    }

    public function warning($message)
    {
        $this->log($message, self::LEVEL_WARNING);
    }

    public function error($message)
    {
        $this->log($message, self::LEVEL_ERROR);
    }
}

// Database connection class
class Database
{
    private $connection;
    private $logger;

    public function __construct($host, $user, $pass, $dbName)
    {
        $this->logger = Logger::getInstance();

        try {
            // Simulate connection
            $this->logger->info("Connecting to database $dbName on $host");
            // $this->connection = new PDO("mysql:host=$host;dbname=$dbName", $user, $pass);
            // $this->connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // For testing, we'll simulate the connection
            $this->connection = new stdClass();
            $this->connection->connected = true;
            $this->connection->host = $host;
            $this->connection->user = $user;
            $this->connection->database = $dbName;

            $this->logger->info("Database connection established");
        } catch (Exception $e) {
            $this->logger->error("Database connection failed: " . $e->getMessage());
            throw $e;
        }
    }

    public function query($sql, $params = [])
    {
        $this->logger->debug("Executing SQL: $sql");

        // Simulate query execution
        $result = new stdClass();
        $result->sql = $sql;
        $result->params = $params;
        $result->success = true;
        $result->timestamp = time();

        // Simulate different result sets based on queries
        if (stripos($sql, 'SELECT') === 0) {
            if (stripos($sql, 'users') !== false) {
                $result->rows = [
                    ['id' => 1, 'name' => 'John Doe', 'email' => 'john@example.com'],
                    ['id' => 2, 'name' => 'Jane Smith', 'email' => 'jane@example.com'],
                    ['id' => 3, 'name' => 'Bob Johnson', 'email' => 'bob@example.com']
                ];
            } else if (stripos($sql, 'products') !== false) {
                $result->rows = [
                    ['id' => 1, 'name' => 'Laptop', 'price' => 999.99],
                    ['id' => 2, 'name' => 'Smartphone', 'price' => 499.50],
                    ['id' => 3, 'name' => 'Tablet', 'price' => 299.75]
                ];
            } else {
                $result->rows = [];
            }
        } else if (stripos($sql, 'INSERT') === 0) {
            $result->insertId = rand(1000, 9999);
            $result->affectedRows = 1;
        } else if (stripos($sql, 'UPDATE') === 0 || stripos($sql, 'DELETE') === 0) {
            $result->affectedRows = rand(1, 5);
        }

        return $result;
    }

    public function getConnection()
    {
        return $this->connection;
    }

    public function close()
    {
        $this->logger->debug("Closing database connection");
        $this->connection = null;
    }
}

// User class
class User
{
    private $id;
    private $name;
    private $email;
    private $role;
    private $created;

    public function __construct($data = [])
    {
        $this->id = $data['id'] ?? null;
        $this->name = $data['name'] ?? '';
        $this->email = $data['email'] ?? '';
        $this->role = $data['role'] ?? 'user';
        $this->created = $data['created'] ?? date('Y-m-d H:i:s');
    }

    public function getId()
    {
        return $this->id;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getEmail()
    {
        return $this->email;
    }

    public function getRole()
    {
        return $this->role;
    }

    public function isAdmin()
    {
        return $this->role === 'admin';
    }

    public function toArray()
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'role' => $this->role,
            'created' => $this->created
        ];
    }
}

// UserRepository class
class UserRepository
{
    private $db;
    private $logger;

    public function __construct(Database $db)
    {
        $this->db = $db;
        $this->logger = Logger::getInstance();
    }

    public function findAll()
    {
        $this->logger->debug("Finding all users");
        $result = $this->db->query("SELECT * FROM users ORDER BY name");

        $users = [];
        foreach ($result->rows as $row) {
            $users[] = new User($row);
        }

        return $users;
    }

    public function findById($id)
    {
        $this->logger->debug("Finding user by id: $id");
        $result = $this->db->query("SELECT * FROM users WHERE id = ?", [$id]);

        if (!empty($result->rows)) {
            return new User($result->rows[0]);
        }

        return null;
    }

    public function create(User $user)
    {
        $this->logger->info("Creating new user: " . $user->getEmail());
        $userData = $user->toArray();
        unset($userData['id']); // don't insert ID

        $columns = implode(', ', array_keys($userData));
        $placeholders = implode(', ', array_fill(0, count($userData), '?'));

        $result = $this->db->query(
            "INSERT INTO users ($columns) VALUES ($placeholders)",
            array_values($userData)
        );

        return $result->insertId;
    }

    public function update(User $user)
    {
        $this->logger->info("Updating user: " . $user->getId());
        $userData = $user->toArray();
        $id = $userData['id'];
        unset($userData['id']); // don't update ID

        $setParts = [];
        foreach (array_keys($userData) as $column) {
            $setParts[] = "$column = ?";
        }
        $setClause = implode(', ', $setParts);

        $values = array_values($userData);
        $values[] = $id; // add ID for WHERE clause

        $result = $this->db->query(
            "UPDATE users SET $setClause WHERE id = ?",
            $values
        );

        return $result->affectedRows > 0;
    }

    public function delete($id)
    {
        $this->logger->warning("Deleting user: $id");
        $result = $this->db->query("DELETE FROM users WHERE id = ?", [$id]);
        return $result->affectedRows > 0;
    }
}

// Application class
class Application
{
    private $config;
    private $logger;
    private $db;
    private $userRepo;

    public function __construct($config)
    {
        $this->config = $config;
        $this->logger = Logger::getInstance(
            $config['debug'] ? 'php://stdout' : '/tmp/app.log',
            $config['debug'] ? Logger::LEVEL_DEBUG : Logger::LEVEL_INFO
        );

        $this->logger->info("{$this->config['app_name']} v{$this->config['version']} starting up");

        try {
            $this->db = new Database(
                $this->config['db']['host'],
                $this->config['db']['user'],
                $this->config['db']['pass'],
                $this->config['db']['name']
            );

            $this->userRepo = new UserRepository($this->db);
        } catch (Exception $e) {
            $this->logger->error("Application initialization failed: " . $e->getMessage());
            throw $e;
        }
    }

    public function getConfig()
    {
        return $this->config;
    }

    public function getUserRepo()
    {
        return $this->userRepo;
    }

    public function processRequest($action, $params = [])
    {
        $this->logger->info("Processing request: $action");

        switch ($action) {
            case 'list_users':
                $users = $this->userRepo->findAll();
                return array_map(function ($user) {
                    return $user->toArray();
                }, $users);

            case 'get_user':
                $user = $this->userRepo->findById($params['id']);
                return $user ? $user->toArray() : null;

            case 'create_user':
                $user = new User($params);
                $id = $this->userRepo->create($user);
                return ['success' => true, 'id' => $id];

            case 'update_user':
                $user = new User($params);
                $success = $this->userRepo->update($user);
                return ['success' => $success];

            case 'delete_user':
                $success = $this->userRepo->delete($params['id']);
                return ['success' => $success];

            default:
                $this->logger->warning("Unknown action: $action");
                return ['error' => 'Unknown action'];
        }
    }

    public function shutdown()
    {
        $this->logger->info("Application shutting down");
        $this->db->close();
    }
}

// Utility functions
function formatCurrency($amount, $currency = 'USD')
{
    $symbols = ['USD' => '$', 'EUR' => '€', 'GBP' => '£', 'JPY' => '¥'];
    $symbol = $symbols[$currency] ?? '';

    return $symbol . number_format($amount, 2);
}

function generateToken($length = 32)
{
    return bin2hex(random_bytes($length / 2));
}

function validateEmail($email)
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

// Initialize application
$logger = Logger::getInstance();
$logger->info("Initializing application");

try {
    // Create and run the application
    $app = new Application($config);

    // Process some sample requests
    $results = [];

    // List users
    $results['users'] = $app->processRequest('list_users');

    // Get user
    $results['user'] = $app->processRequest('get_user', ['id' => 2]);

    // Create user
    $results['create'] = $app->processRequest('create_user', [
        'name' => 'Sarah Williams',
        'email' => 'sarah@example.com',
        'role' => 'editor'
    ]);

    // Format a currency value
    $results['formatted_price'] = formatCurrency(1234.56);

    // Generate a token
    $results['token'] = generateToken();

    // Email validation
    $results['valid_email'] = validateEmail('test@example.com');
    $results['invalid_email'] = validateEmail('not-an-email');

    // Shut down the application
    $app->shutdown();

    echo "Application executed successfully\n";

    // Return all results for testing
    return [
        'status' => 'success',
        'message' => 'Application test completed',
        'results' => $results
    ];
} catch (Exception $e) {
    $logger->error("Application failed: " . $e->getMessage());

    return [
        'status' => 'error',
        'message' => $e->getMessage()
    ];
}
