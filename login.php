<?php
declare(strict_types=1);

require_once("php_includes/base.inc.php");

// Prevent direct access if already logged in
if (isLoggedIn() || checkRem()) {
	redirect("index.php");
	exit();
}

$error = '';

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	// Verify CSRF token
	if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
		$error = 'Invalid request';
	} else {
		$username = sanitizeInput($_POST['uname'] ?? '');
		$password = $_POST['pass'] ?? '';
		$rememberMe = isset($_POST['rememberme']);
		
		if (empty($username) || empty($password)) {
			$error = 'Please enter both username and password';
		} else {
			$log = login($username, $password, $rememberMe);
			
			switch ($log) {
				case 0:
					redirect("index.php");
					exit();
				case 1:
					$error = 'Invalid username';
					break;
				case 2:
					$error = 'Invalid password';
					break;
				default:
					$error = 'An unexpected error occurred';
					break;
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
	<title><?php echo htmlspecialchars($cminfo['pdn'] ?? 'Police Database'); ?> - Secure Login</title>
	
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
		<form method="post" action="login.php" autocomplete="off">
			<input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
			<input type="text" name="uname" placeholder="Username" required 
				   value="<?php echo isset($_POST['uname']) ? htmlspecialchars($_POST['uname']) : ''; ?>">
			<input type="password" name="pass" placeholder="Password" required>
			<div id="remdiv">
				<input type="checkbox" name="rememberme" id="rem" checked>
				<label for="rem">Remember Me</label>
			</div>
			<div class="forgot">
				<input type="submit" value="Login">
			</div>
		</form>
	</div>
	<div class="login-bottom">
		<h3>New Officer? &nbsp;<a href="register.php">REGISTER</a></h3>
	</div>
</div>
<div class="copyright">
	<p class="copyright">&copy; Copyright <?php echo date('Y'); ?> <a href="https://www.jamee9.dev/" target="_blank" rel="noopener">Jamee9.Dev</a></p>
</div>
</body>
</html>