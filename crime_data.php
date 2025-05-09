<?php
declare(strict_types=1);

require_once("php_includes/base.inc.php");

// Check permissions
if (!hasPerm("officer")) {
    redirect("index.php");
    exit();
}

// Validate CSRF token
if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
    redirect("crime.php");
    exit();
}

// Validate required fields
if (!isset($_POST['crim']) || empty(trim($_POST['crim']))) {
    redirect("crime.php");
    exit();
}

try {
    // Get and sanitize input
    $crim = trim($_POST['crim']);
    $crid = getCiv($crim);
    
    if (!$crid) {
        $crid = createCiv(ucwords($crim));
    }
    
    $crim = $crid['name'];
    sCiv($crid['id']);

    // Handle bail/bond
    $bailbond = isset($_POST['bailbond']) ? safeNum($_POST['bailbond']) : 0;

    // Handle arrest record
    if (isset($_POST['crime']) && !empty($_POST['crime'])) {
        if (!isset($_SESSION['arrandom'])) {
            $_SESSION['arrandom'] = $_POST['random'] + 10;
        }

        if ($_POST['random'] != $_SESSION['arrandom']) {
            $arr = newArrest(
                $crid['id'],
                $_POST['crime'],
                $_POST['evi'] ?? '',
                $_POST['time'],
                $_POST['date'],
                $_POST['ibail'],
                $bailbond
            );
            $_SESSION['arrandom'] = $_POST['random'];
        }
    }

    // Get user timezone
    $usrTZ = filter_input(INPUT_COOKIE, "LSTZ", FILTER_SANITIZE_STRING) ?: "UTC";

    // Get system info
    $cminfo = getInfo("cminfo");
    $cminfo = json_decode($cminfo['data'] ?? '{}', true);

    // Get arrest and warrant records
    $totalArr = getArrests($crid['id']);
    $numerArr = count($totalArr);
    $totalWrr = getWarrants($crid['id']);
    $numerWrr = count($totalWrr);
} catch (Exception $e) {
    error_log("Error in crime_data.php: " . $e->getMessage());
    redirect("crime.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <title><?php echo htmlspecialchars($cminfo['pda']); ?> - Criminal Database</title>
    <meta name="description" content="<?php echo htmlspecialchars($cminfo['pdn']); ?> - Criminal Information">
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
                            <h1>View Criminal Search History</h1>
                            <h2>Mess up a crime? Please tell Cole for now.</h2>
                        </header>
                    </div>
                </div>
                <div class="row">
                    <div class="col-12">
                        <div class="alert alert-warning fade in">
                            <i class="fa fa-exclamation-triangle" aria-hidden="true"></i>
                            <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
                            <p>Please read this regarding the future of the police database, <a href="notice.php" rel="noopener noreferrer">HERE</a></p>
                        </div>
                        <article class="inner">
                            <div class="row">
                                <div class="col-12">
                                    <h4>
                                        View/Add Criminal Record - <?php echo htmlspecialchars(ucwords($crim)); ?>
                                        <?php if (isCop($crim)): ?>
                                            <span class="text-danger">(OFFICER)</span>
                                        <?php endif; ?>
                                        (<strong><?php echo $numerArr; ?></strong> Priors)
                                        <br>
                                        <?php if ($totalWrr): ?>
                                            <strong><span class="text-danger"><?php echo $numerWrr; ?> Active Warrant</span> - <a href="warrants.php" rel="noopener noreferrer">View Warrants</a></strong>
                                        <?php else: ?>
                                            <strong><span class="text-success">0 Active Warrants</span></strong>
                                        <?php endif; ?>
                                    </h4>
                                </div>
                            </div>
                            <form id="post-comment" class="inner" action="crime_data.php" method="post">
                                <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                <div class="row">
                                    <div class="form-group col-2">
                                        <label for="name">Suspect Name <span class="form-required" title="This field is required.">*</span></label>
                                        <input autocomplete="off" list="autocomp" type="text" name="crim" class="form-control" value="<?php echo htmlspecialchars($crim); ?>" id="name" required>
                                        <datalist id="autocomp"></datalist>
                                    </div>
                                    <div class="form-group col-2">
                                        <label for="time">Total Time <span class="form-required" title="This field is required.">*</span></label>
                                        <input type="number" name="time" placeholder="In minutes" class="form-control" id="time" required min="0">
                                        <input type="hidden" name="random" value="<?php echo rand(); ?>">
                                    </div>
                                    <div class="form-group col-2">
                                        <label for="date">Date <span class="form-required" title="This field is required.">*</span></label>
                                        <input type="date" name="date" required value="<?php echo date("Y-m-d"); ?>" class="form-control" id="date">
                                    </div>
                                    <div class="form-group col-1">
                                        <div class="form-check">
                                            <label class="form-check-label">
                                                <input type="radio" name="ibail" value="Bail" class="form-check-input" checked>
                                                Bail
                                            </label>
                                            <label class="form-check-label">
                                                <input type="radio" name="ibail" value="Bond" class="form-check-input">
                                                Bond
                                            </label>
                                        </div>
                                    </div>
                                    <div class="form-group col-2">
                                        <label for="bond">Bail/Bond</label>
                                        <input type="number" name="bailbond" placeholder="If none leave blank" class="form-control" id="bond" min="0">
                                    </div>
                                    <div class="form-group col-4">
                                        <label for="crime">Crime(s) <span class="form-required" title="This field is required.">*</span></label>
                                        <input type="text" name="crime" placeholder="Separate each crime with a comma" class="form-control" id="crime" required>
                                    </div>
                                    <div class="form-group col-8">
                                        <label for="evi">Evidence (Please keep links short, use <a href="https://goo.gl/" target="_blank" rel="noopener noreferrer">https://goo.gl</a> if needed. If posting pictures, please link to a <a href="http://imgur.com/" target="_blank" rel="noopener noreferrer">Imgur</a> album)</label>
                                        <input type="text" name="evi" placeholder="Provide any evidence if needed" class="form-control" id="evi">
                                    </div>
                                </div>
                                <button type="submit" class="btn btn-color">
                                    <i class="glyphicon glyphicon-send" aria-hidden="true"></i>
                                    Add Record
                                </button>
                            </form>
                            <?php if ($arrests): ?>
                            <div class="table-responsive">
                                <table class="table table-striped table-hover" aria-label="Arrest Records">
                                    <thead>
                                        <tr>
                                            <th scope="col">Time Entered</th>
                                            <th scope="col">Date</th>
                                            <th scope="col">Name</th>
                                            <th scope="col">Crime</th>
                                            <th scope="col">Time</th>
                                            <th scope="col">Bail</th>
                                            <th scope="col">Bond</th>
                                            <th scope="col">Evidence</th>
                                            <th scope="col">Arresting Officer</th>
                                            <th scope="col">Processing Officer</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php
                                        $format = "Y-m-d H:i:s";
                                        foreach ($arrests as $arrest):
                                            $aoffi = getUser($arrest['copid'], U_ID);
                                            $tproc = getUser($arrest['docid'], U_ID);
                                            $utcTS = antiXSS($arrest['RealDate']);
                                            $usrTS = date_create($utcTS, new DateTimeZone("UTC"))
                                                ->setTimeZone(new DateTimeZone($usrTZ))
                                                ->format($format);
                                            $poffi = ($arrest['proc'] == 0) ? 
                                                "<span class='text-danger'>Not Processed</span>" : 
                                                htmlspecialchars($tproc['display']);
                                            $bond = ($arrest['bondid'] == -1) ? "No" : "Yes";
                                            $bail = ($arrest['bail'] == 0) ? "No" : "$" . number_format($arrest['bail']);
                                        ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($usrTS); ?></td>
                                            <td><?php echo htmlspecialchars($arrest['date']); ?></td>
                                            <td><?php echo htmlspecialchars($crim); ?></td>
                                            <td><?php echo titleFormat(htmlspecialchars($arrest['crimes'])); ?></td>
                                            <td><?php echo htmlspecialchars(number_format($arrest['time'])); ?></td>
                                            <td><?php echo $bail; ?></td>
                                            <td><?php echo $bond; ?></td>
                                            <td><?php echo titleFormat(htmlspecialchars($arrest['evd'])); ?></td>
                                            <td><?php echo htmlspecialchars($aoffi['display']); ?></td>
                                            <td><?php echo $poffi; ?></td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                            <?php else: ?>
                            <p class="text-center">This person has no arrests!</p>
                            <?php endif; ?>
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
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        let lastVal = "";
        function autocomp() {
            const cVal = document.getElementById("name").value;
            if (cVal.length >= 2 && lastVal !== cVal) {
                fetch("autocomplete.php?name=" + encodeURIComponent(cVal))
                    .then(response => response.text())
                    .then(data => {
                        document.getElementById("autocomp").innerHTML = data;
                    })
                    .catch(error => console.error('Error:', error));
                lastVal = cVal;
            }
        }
        setInterval(autocomp, 2000);
    });
    </script>
</body>
</html>