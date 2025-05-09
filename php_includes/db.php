<?php
declare(strict_types=1);

//error_reporting(E_ALL);
ini_set('display_errors',0);
ini_set('display_startup_errors',0);

// Database configuration
const DB_CONFIG = [
	'host' => 'localhost',
	'dbname' => 'police',
	'username' => 'root',
	'password' => '',
	'charset' => 'utf8mb4'
];

/**
 * Generate a PDO connection with proper error handling
 * 
 * @param string $dbname Database name
 * @param string $user Username
 * @param string $pass Password
 * @param string $host Host
 * @return PDO
 * @throws PDOException
 */
function genPDO(
	string $dbname = DB_CONFIG['dbname'],
	string $user = DB_CONFIG['username'],
	string $pass = DB_CONFIG['password'],
	string $host = DB_CONFIG['host']
): PDO {
	$dsn = sprintf(
		"mysql:host=%s;dbname=%s;charset=%s",
		$host,
		$dbname,
		DB_CONFIG['charset']
	);
	
	$options = [
		PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
		PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
		PDO::ATTR_EMULATE_PREPARES => false,
	];
	
	try {
		$pdo = new PDO($dsn, $user, $pass, $options);
		return $pdo;
	} catch (PDOException $e) {
		// Log the error but don't expose details to the user
		error_log("Database connection failed: " . $e->getMessage());
		throw new PDOException("Database connection failed. Please try again later.");
	}
}

// Initialize the database connection
try {
	$pdo = genPDO();
} catch (PDOException $e) {
	// Handle connection error
	die("Database connection failed. Please try again later.");
}
?>