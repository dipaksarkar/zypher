<?php

/**
 * OOP functionality test file
 * Tests classes, inheritance, interfaces, traits
 */

// Interface definition
interface PaymentInterface
{
    public function pay($amount);
    public function getBalance();
}

// Trait definition
trait LoggableTrait
{
    private $logEntries = [];

    public function log($message)
    {
        $this->logEntries[] = date('Y-m-d H:i:s') . ": $message";
    }

    public function getLogs()
    {
        return $this->logEntries;
    }
}

// Base abstract class
abstract class Account
{
    protected $balance = 0;
    protected $name;

    public function __construct($name, $initialBalance = 0)
    {
        $this->name = $name;
        $this->balance = $initialBalance;
        $this->onConstruct();
    }

    abstract protected function onConstruct();

    public function deposit($amount)
    {
        $this->balance += $amount;
        return $this;
    }

    public function getBalance()
    {
        return $this->balance;
    }

    public function __toString()
    {
        return "Account {$this->name} with balance: {$this->balance}";
    }
}

// Child class implementing interface and using trait
class BankAccount extends Account implements PaymentInterface
{
    use LoggableTrait;

    private $accountNumber;
    private static $lastAccountNumber = 1000;

    protected function onConstruct()
    {
        $this->accountNumber = ++self::$lastAccountNumber;
        $this->log("Account created with number: {$this->accountNumber}");
    }

    public function withdraw($amount)
    {
        if ($amount > $this->balance) {
            throw new Exception("Insufficient funds");
        }
        $this->balance -= $amount;
        $this->log("Withdrew $amount, new balance: {$this->balance}");
        return $this;
    }

    public function pay($amount)
    {
        try {
            $this->withdraw($amount);
            $this->log("Payment of $amount processed");
            return true;
        } catch (Exception $e) {
            $this->log("Payment failed: " . $e->getMessage());
            return false;
        }
    }

    public function getAccountDetails()
    {
        return [
            'name' => $this->name,
            'balance' => $this->balance,
            'accountNumber' => $this->accountNumber
        ];
    }

    public static function getNextAccountNumber()
    {
        return self::$lastAccountNumber + 1;
    }
}

// Anonymous class implementation
$processor = new class() {
    public function processPayment(PaymentInterface $account, $amount)
    {
        return $account->pay($amount);
    }
};

// Using the class hierarchy
$account = new BankAccount("John Doe", 1000);
echo $account . "\n";

$account->deposit(500);
echo "New balance after deposit: " . $account->getBalance() . "\n";

$paymentSuccess = $processor->processPayment($account, 750);
echo "Payment " . ($paymentSuccess ? "succeeded" : "failed") . "\n";

// Display account details
$details = $account->getAccountDetails();
echo "Account details:\n";
foreach ($details as $key => $value) {
    echo "$key: $value\n";
}

// Check logs
echo "Log entries:\n";
foreach ($account->getLogs() as $log) {
    echo "- $log\n";
}

// Test static methods
echo "Next account number will be: " . BankAccount::getNextAccountNumber() . "\n";

// Return a result for testing
return [
    'status' => 'success',
    'message' => 'OOP functionality test completed',
    'accountBalance' => $account->getBalance()
];
