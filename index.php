<?php
declare(strict_types=1);

require_once("php_includes/base.inc.php");

// Check if user is logged in
if (!isLoggedIn()) {
	redirect("login.php");
	exit();
}

try {
	$usr = getUser($_SESSION['uname'], U_UNAME);
	$cminfo = getInfo("cminfo");
	$cminfo = json_decode($cminfo['data'] ?? '{}', true);

	// Redirect pending users to settings
	if ($usr['dept'] == PENDING) {
		redirect("settings.php");
		exit();
	}
} catch (Exception $e) {
	error_log("Error in index.php: " . $e->getMessage());
	die("An error occurred. Please try again later.");
}
?>
<!DOCTYPE html>
<html lang="en-US">
	<head>

		<!-- Meta -->
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="description" content="<?php echo htmlspecialchars($cminfo['pdn'] ?? 'Police Database'); ?> - Criminal Database Homepage">
		<meta name="author" content="Cole, Scott Harm (Retired)">
		<meta name="robots" content="noindex, nofollow">
		<meta name="referrer" content="same-origin">
		
		<title><?php echo htmlspecialchars($cminfo['pdn'] ?? 'Police Database'); ?> Database</title>

		<!-- Favicons -->
		<link rel="shortcut icon" href="img/favicons/favicon.png">
		<link rel="apple-touch-icon" href="img/favicons/icon.png">
		<link rel="apple-touch-icon" sizes="72x72" href="img/favicons/72x72.png">
		<link rel="apple-touch-icon" sizes="114x114" href="img/favicons/114x114.png">
		
		<!-- CSS -->
		<link rel="stylesheet" href="css/reset.css">
		<link rel="stylesheet" href="css/bootstrap.min.css">
		<link rel="stylesheet" href="css/font-awesome.min.css">
		<link href="https://fonts.googleapis.com/css?family=Raleway:300|Muli:300" rel="stylesheet" type="text/css">
		<link rel="stylesheet" href="css/idangerous.swiper.css">
		<link rel="stylesheet" href="css/style.css">
		<link rel="stylesheet" href="css/ticker.css">

		<!-- JavaScript -->
		<script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=" crossorigin="anonymous"></script>
		<script src="js/tzselect.js"></script>
		<script>
			document.addEventListener('DOMContentLoaded', function() {
				var timezone = jstz.determine();
				let response_text = 'UTC';
				if (typeof (timezone) !== 'undefined') {
					response_text = timezone.name();
				}
				document.cookie = "LSTZ=" + response_text + "; path=/; secure; samesite=Lax";
			});
		</script>
	</head>
	<body>
		<div id="overlay"></div>
		<div id="top">
			<a href="#" id="sidebar-button" aria-label="Toggle Sidebar"></a>
			<header id="logo">
				<img src="img/logo.png" alt="Logo" width="150" height="50">
			</header>
		</div>
		<div id="main-wrapper">
			<?php require_once("boloTicker.php"); ?>
			<div id="content">
				<div id="fullscreen-slider" class="swiper-container">
					<div class="swiper-wrapper">
						<div class="swiper-slide overlay overlay-dark-25 white" style="background-image: url(img/slides/front.png)">
							<h1>Welcome to the <?php echo htmlspecialchars($cminfo['cmn'] ?? 'Police'); ?> police database!<br>Build Version 1.1.2</h1>
							<?php
							if ($usr['dept'] != -1) {
								$dname = explode(" ", $usr['display']);
								$ln = count($dname) - 1;
								echo "<br/><h2 style=\"color: black\">Welcome, " . htmlspecialchars(getRankName($usr['id'])) . " " . htmlspecialchars($dname[$ln]) . "</h2>";
							}
							?>
						</div>
					</div>
				</div>
			</div>
			<?php require_once("sidebar.php"); ?>
			<footer>
				<p class="copyright">&copy; Copyright <?php echo date('Y'); ?> <a href="https://www.jamee9.dev/" target="_blank" rel="noopener">Jamee9.Dev</a></p>
			</footer>
		</div>

		<!-- JavaScripts -->
		<script src="js/bootstrap.min.js"></script>
		<script src="js/swiper/idangerous.swiper.min.js"></script>
		<script src="js/masonry/masonry.pkgd.min.js"></script>
		<script src="js/isotope/jquery.isotope.min.js"></script>
		<script src="js/custom.js"></script>
		<script src="js/ticker.js"></script>

	</body>
</html>