<?php
declare(strict_types=1);

require_once("php_includes/base.inc.php");

// Check permissions
if (!hasPerm("officer")) {
    redirect("index.php");
    exit();
}

try {
    // Get system info
    $cminfo = getInfo("cminfo");
    $cminfo = json_decode($cminfo['data'] ?? '{}', true);
} catch (Exception $e) {
    error_log("Error in crime.php: " . $e->getMessage());
    $cminfo = ['pda' => 'System', 'pdn' => 'System'];
}
?>
<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title><?php echo htmlspecialchars($cminfo['pda']); ?> - Criminal Database</title>
    <meta name="description" content="<?php echo htmlspecialchars($cminfo['pdn']); ?> - Criminal Database">
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
                            <h1>Criminal Database</h1>
                        </header>
                    </div>
                </div>
                <div class="row">
                    <div class="col-12">
                        <article class="inner">
                            <div class="row">
                                <div class="col-12">
                                    <h4>Search/Add Criminals:</h4>
                                    <form id="post-comment" class="inner" action="crime_data.php" method="post">
                                        <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                        <div class="row">
                                            <div class="form-group col-4">
                                                <label for="name">Name <span class="form-required" title="This field is required.">*</span></label>
                                                <?php autoComp("crim", "name"); ?>
                                            </div>
                                        </div>
                                        <button type="submit" class="btn btn-color">
                                            <i class="glyphicon glyphicon-send" aria-hidden="true"></i>
                                            Search Database
                                        </button>
                                    </form>
                                    <h4>Can't find SOP's? Criminal Code? Lawyer's? <a href="info.php" rel="noopener noreferrer">Look no further!</a></h4>
                                </div>
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