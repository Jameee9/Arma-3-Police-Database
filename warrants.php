<?php
declare(strict_types=1);

require_once("php_includes/base.inc.php");

// Check permissions
if (!hasPerm("officer")) {
	redirect("/index.php");
	exit();
}

try {
	// Get warrants
	$stmt = getDB()->prepare("SELECT * FROM `warrants` WHERE `active` = 0 ORDER BY `id` DESC");
	$stmt->execute();
	$warrants = $stmt->fetchAll();
	$acnt = count($warrants);

	// Get system info
	$cminfo = getInfo("cminfo");
	$cminfo = json_decode($cminfo['data'] ?? '{}', true);
} catch (Exception $e) {
	error_log("Error in warrants.php: " . $e->getMessage());
	$warrants = [];
	$acnt = 0;
	$cminfo = ['pda' => 'System', 'pdn' => 'System'];
}
?>
<!DOCTYPE html>
<html lang="en-US">
	<head>

		<!-- Meta -->
		<meta charset="UTF-8">
		<title><?php echo htmlspecialchars($cminfo['pda']); ?> - Active Warrants</title>
		<meta name="description" content="<?php echo htmlspecialchars($cminfo['pdn']); ?> - Active Warrants">
		<meta name="author" content="Cole, Scott Harm (Retired)">
		<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta name="robots" content="noindex, nofollow">
		<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://ajax.googleapis.com; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;">

		<!-- Favicons -->
		<link rel="shortcut icon" href="img/favicons/favicon.png">
		<link rel="apple-touch-icon" href="img/favicons/icon.png">
		<link rel="apple-touch-icon" sizes="72x72" href="img/favicons/72x72.png">
		<link rel="apple-touch-icon" sizes="114x114" href="img/favicons/114x114.png">
		
		<!-- CSS -->
		<link rel="stylesheet" href="css/reset.css">
		<link rel="stylesheet" href="css/bootstrap.min.css">
		<link rel="stylesheet" href="css/font-awesome.min.css">
		<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Raleway:300|Muli:300" crossorigin>
		<link rel="stylesheet" href="css/idangerous.swiper.css">
		<link rel="stylesheet" href="css/style.css">
		<link rel="stylesheet" href="css/ticker.css">
		
		<!-- Scripts -->
		<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js" integrity="sha256-36cp7Co6/epsqWOBZtlbsXK4Q5n/0e2Zb+6jXQ=" crossorigin="anonymous"></script>
	</head>
	<body>
		<div id="overlay"></div>
		<div id="top">
			<a href="#" id="sidebar-button" aria-label="Toggle Sidebar"></a>
			<header id="logo">
				<img src="img/logo.png" alt="Logo">
			</header>
		</div>
		<div id="main-wrapper">
			<?php require_once("boloTicker.php"); ?>
			<div id="content">
				<div class="container-fluid">
					<div id="heading" class="row">
						<div class="col-12">
							<header>
								<h1>All Active Warrants</h1>
							</header>
						</div>
					</div>
					<div class="row">
						<div class="col-12">
							<article class="inner">
								<div class="row">
									<div class="col-12">
										<h4>Total Active Warrants - <?php echo $acnt; ?></h4>
									</div>
								</div>
								<div class="table-responsive">
									<?php if ($warrants): ?>
									<table class="table table-striped table-hover" aria-label="Active Warrants">
										<thead>
											<tr>
												<th scope="col">Name</th>
												<th scope="col">Approving Judge</th>
												<th scope="col">Crimes</th>
												<th scope="col">Type</th>
												<th scope="col">Date</th>
												<th scope="col">Link</th>
											</tr>
										</thead>
										<tbody>
											<?php foreach ($warrants as $warrant): 
												$cname = getCiv($warrant['uid'], U_ID);
											?>
											<tr>
												<td><?php echo htmlspecialchars($cname['name']); ?></td>
												<td><?php echo htmlspecialchars($warrant['dojname']); ?></td>
												<td><?php echo titleFormat(htmlspecialchars($warrant['crimes'])); ?></td>
												<td><?php echo htmlspecialchars($warrant['wtype']); ?></td>
												<td><?php echo htmlspecialchars($warrant['date']); ?></td>
												<td><a href="<?php echo htmlspecialchars($warrant['wlink']); ?>" target="_blank" rel="noopener noreferrer">WARRANT LINK</a></td>
											</tr>
											<?php endforeach; ?>
										</tbody>
									</table>
									<?php else: ?>
									<p class="text-center">There are currently no active warrants!</p>
									<?php endif; ?>
								</div>
							</article>
						</div>
					</div>
				</div>
			</div>
			<?php require_once("sidebar.php"); ?>
			<footer>
				<p class="copyright">&copy; Copyright <?php echo date('Y'); ?> <a href="http://coltonbrister.com" target="_blank" rel="noopener noreferrer">Colton Brister</a></p>
			</footer>
		</div>

		<!-- JavaScripts -->
		<script src="js/jquery.min.js"></script>
		<script src="js/bootstrap.min.js"></script>
		<script src="js/swiper/idangerous.swiper.min.js"></script>
		<script src="js/masonry/masonry.pkgd.min.js"></script>
		<script src="js/isotope/jquery.isotope.min.js"></script>
		<script src="js/custom.js"></script>
		<script src="js/ticker.js"></script>

	</body>
</html>