<?php
declare(strict_types=1);

require_once("php_includes/base.inc.php");

// Prevent direct access if already logged in
if (isLoggedIn() || checkRem()) {
    redirect("index.php");
    exit();
}

$error = '';
$success = '';

// Handle registration form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        $error = 'Invalid request';
    } else {
        $username = sanitizeInput($_POST['uname'] ?? '');
        $password = $_POST['pass'] ?? '';
        $confirmPassword = $_POST['cpass'] ?? '';
        
        if (empty($username) || empty($password) || empty($confirmPassword)) {
            $error = 'Please fill in all fields';
        } elseif ($password !== $confirmPassword) {
            $error = 'Passwords do not match';
        } elseif (strlen($password) < 8) {
            $error = 'Password must be at least 8 characters long';
        } else {
            try {
                $pdo = getDB();
                
                // Check if username already exists
                $stmt = $pdo->prepare("SELECT id FROM users WHERE username = :username");
                $stmt->bindParam(":username", $username);
                $stmt->execute();
                
                if ($stmt->rowCount() > 0) {
                    $error = 'Username already exists';
                } else {
                    // Create new user
                    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("INSERT INTO users (username, password, created_at) VALUES (:username, :password, NOW())");
                    $stmt->bindParam(":username", $username);
                    $stmt->bindParam(":password", $hashedPassword);
                    
                    if ($stmt->execute()) {
                        $success = 'Registration successful! You can now log in.';
                    } else {
                        $error = 'Registration failed. Please try again.';
                    }
                }
            } catch (PDOException $e) {
                error_log("Registration failed: " . $e->getMessage());
                $error = 'An unexpected error occurred';
            }
        }
    }
}

$cminfo = getInfo("cminfo");
$cminfo = json_decode($cminfo['data'] ?? '{}', true);
?>
<!DOCTYPE HTML>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
    <title><?php echo htmlspecialchars($cminfo['pdn'] ?? 'Police Database'); ?> - Register</title>
    
    <!-- CSS -->
    <link href="css/styleLogin.css" rel="stylesheet" type="text/css" media="all"/>
    <link href='https://fonts.googleapis.com/css?family=Roboto:500,900italic,900,400italic,100,700italic,300,700,500italic,100italic,300italic,400' rel='stylesheet' type='text/css'>
    <link href='https://fonts.googleapis.com/css?family=Droid+Serif:400,700,400italic,700italic' rel='stylesheet' type='text/css'>
</head>
<body>
<div class="login">
    <div class="login-top">
        <h1><?php echo htmlspecialchars($cminfo['pdn'] ?? 'Police Database'); ?></h1>
        <?php if ($error): ?>
            <div class="error-message"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="success-message"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>
        <form method="post" action="register.php" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
            <input type="text" name="uname" placeholder="Username" required 
                   value="<?php echo isset($_POST['uname']) ? htmlspecialchars($_POST['uname']) : ''; ?>">
            <input type="password" name="pass" placeholder="Password" required>
            <input type="password" name="cpass" placeholder="Confirm Password" required>
            <div class="forgot">
                <input type="submit" value="Register">
            </div>
        </form>
    </div>
    <div class="login-bottom">
        <h3>Already have an account? &nbsp;<a href="login.php">LOGIN</a></h3>
    </div>
</div>
<div class="copyright">
    <p class="copyright">&copy; Copyright <?php echo date('Y'); ?> <a href="https://www.jamee9.dev/" target="_blank" rel="noopener">Jamee9.Dev</a></p>
</div>
</body>
</html>