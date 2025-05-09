<?php
declare(strict_types=1);

// Error reporting for development
error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');

// Start session with secure settings
if (session_status() === PHP_SESSION_NONE) {
    $sessionOptions = [
        'cookie_httponly' => true,
        'cookie_secure' => true,
        'cookie_samesite' => 'Lax',
        'use_strict_mode' => true
    ];
    
    if (session_start($sessionOptions) === false) {
        die('Failed to start session');
    }
}

// Security headers
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\' https:; style-src \'self\' \'unsafe-inline\' https:; img-src \'self\' data: https:; font-src \'self\' https:;');

require_once("db.php");
require_once("query.php");

/**
 * Get database connection
 * 
 * @return PDO
 */
function getDB(): PDO {
    global $pdo;
    return $pdo;
}

/* <---UNCOMMENT BELOW IF YOU USE SSL--->
if(!isset($_SERVER['HTTPS']) && !strstr($_SERVER["HTTP_CF_VISITOR"], "https")) {
	header("Location: https://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]", true, 303);
	exit();
}
*/

// Handle Cloudflare IP
if (isset($_SERVER["HTTP_CF_CONNECTING_IP"])) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER["HTTP_CF_CONNECTING_IP"];
}

// Constants
define('U_ID', 0);
define('U_UNAME', 1);
define('U_DNAME', 2);
define('U_PASS', 4);
define('U_PHONE', 5);
define('U_BADGE', 6);
define('TERM_ID', -2);
define('A_SUCCESS', 0);
define('A_INFO', 1);
define('A_WARN', 2);
define('A_DANGER', 3);
define('L_TERM', 0);
define('L_PRODEMO', 1);
define('L_TRANS', 2);
define('L_EXP', 3);
define('L_LOGIN', 4);
define('L_NAME', 5);
define('PENDING', 9);
define('HOUR', 3600);
define('DAY', 86400);
define('WEEK', 604800);
define('YEAR', 31556926);


/*require( 'php_error.php' );
\php_error\reportErrors();*/

// Initialize user state
$luser = 0;
if (isLoggedIn()) {
    $luser = getUser($_SESSION['uid'], U_ID);
    $_SESSION['uname'] = $luser['uname'];
    if (time() - $_SESSION['ll'] > HOUR * 6) {
        $pdo = getDB();
        $pdo->exec("UPDATE `users` SET `LastLogin` = NOW() WHERE `id` = :id");
    }
} else {
    checkRem();
}

$_SESSION['ll'] = time();

/**
 * Redirect to a URL
 */
function redirect(string $url): void {
    header("Location: $url");
    exit();
}

/**
 * Check if user is logged in
 */
function isLoggedIn(): bool {
    return isset($_SESSION['uid']) && !empty($_SESSION['uid']);
}

/**
 * Check if user has remember me cookie
 */
function checkRem(): bool {
    if (!isset($_COOKIE['r'])) {
        return false;
    }
    
    try {
        $pdo = getDB();
        $hash = hash("sha256", $_COOKIE['r']);
        $stmt = $pdo->prepare("SELECT uid FROM remember WHERE hash = :hash AND expire > NOW()");
        $stmt->bindParam(":hash", $hash);
        $stmt->execute();
        
        if ($stmt->rowCount() > 0) {
            $row = $stmt->fetch();
            $_SESSION['uid'] = $row['uid'];
            return true;
        }
    } catch (PDOException $e) {
        error_log("Remember me check failed: " . $e->getMessage());
    }
    
    return false;
}

/**
 * Handle user login
 */
function login(string $username, string $password, bool $remember = false): int {
    try {
        $pdo = getDB();
        $stmt = $pdo->prepare("SELECT id, password FROM users WHERE username = :username");
        $stmt->bindParam(":username", $username);
        $stmt->execute();
        
        if ($stmt->rowCount() === 0) {
            return 1; // Invalid username
        }
        
        $row = $stmt->fetch();
        if (!password_verify($password, $row['password'])) {
            return 2; // Invalid password
        }
        
        $_SESSION['uid'] = $row['id'];
        
        if ($remember) {
            $token = bin2hex(random_bytes(32));
            $hash = hash("sha256", $token);
            $expire = date('Y-m-d', strtotime('+30 days'));
            
            $stmt = $pdo->prepare("INSERT INTO remember (uid, hash, expire, ip) VALUES (:uid, :hash, :expire, :ip)");
            $stmt->bindParam(":uid", $row['id']);
            $stmt->bindParam(":hash", $hash);
            $stmt->bindParam(":expire", $expire);
            $stmt->bindParam(":ip", $_SERVER['REMOTE_ADDR']);
            $stmt->execute();
            
            setcookie('r', $token, strtotime('+30 days'), '/', '', true, true);
        }
        
        return 0; // Success
    } catch (PDOException $e) {
        error_log("Login failed: " . $e->getMessage());
        return 3; // Database error
    }
}

/**
 * Sanitize input against XSS
 */
function antiXSS(string $str): string {
    return htmlspecialchars(strip_tags(urldecode($str)), ENT_QUOTES, 'UTF-8');
}

function showAlert($txt, $type = A_INFO) {
	$txt = antiXSS($txt);
	$tp = "";
	$icls = "";
	switch($type) {
		case 0:
		$tp = "success";
		$icls = "fa fa-check-circle";
		break;
		case 1:
		$tp = "info";
		$icls = "fa fa-info-circle";
		break;
		case 2:
		$tp = "warning";
		$icls = "fa fa-exclamation-triangle";
		break;
		case 3:
		$tp = "danger";
		$icls = "fa fa-exclamation-circle";
		break;
		default:
		$tp = "info";
	}
	echo "<div class=\"alert alert-$tp fade in\">
												<i class=\"$icls\"></i>
												<button type=\"button\" class=\"close\" data-dismiss=\"alert\" aria-hidden=\"true\">&times;</button>
												<p>$txt</p>
											</div>";
}

function safeNum($num) {
	return intval(str_replace(Array("$", ".", ","), Array("", "", ""), $num));
}

/*function hasPerm($permname) { // OLD HASPERM FUNCTION
	global $pdo;
	if(!isLoggedIn()) return false;
	$stmt = $pdo->prepare("SELECT `plevel`,`dept`, `info`, `rank` FROM `users` WHERE `uname` = :name");
	$stmt->bindParam(":name", $_SESSION['uname']);
	$stmt->execute();
	$res = $stmt->fetch();
	$stmt->closeCursor();
	$stmt = $pdo->prepare("SELECT `perms`,`info` FROM `dept` WHERE `id` = :dept");
	$stmt->bindParam(":dept", $res['dept']);
	$stmt->execute();
	$dp = $stmt->fetch();
	$stmt->closeCursor();

	$dptinf = json_decode($dp['info'], true);
	if(intval($res['rank']) >= intval($dptinf['cmdrank']) && $permname == "pdcmd") return true;
	
	$dperms = json_decode($dp['perms']);
	$uperms = json_decode($res['plevel']);
	$perms = array_merge($uperms, $dperms);
	if(in_array("all", $perms)) return true;
	if(in_array($permname, $perms)) return true;
	return false;
}*/

function hasPerm($permname) {
	global $pdo;
	if(!isLoggedIn()) return false;
	// GET USER DATA / FETCH
	$stmt = $pdo->prepare("SELECT `plevel`,`dept`,`rank` FROM `users` WHERE `id` = :name");
	$stmt->bindParam(":name", $_SESSION['uid']);
	$stmt->execute();
	if(isset($debug)) echo 'Init: '.var_dump($stmt->rowCount());
	$res = $stmt->fetch();
	$stmt->closeCursor();
	// GET DEPARTMENT DATA / FETCH
	$stmt = $pdo->prepare("SELECT `perms`,`info` FROM `dept` WHERE `id` = :dept");
	$stmt->bindParam(":dept", $res['dept']);
	$stmt->execute();
	if(isset($debug)) echo ' Init2: '.var_dump($stmt->rowCount());
	$dp = $stmt->fetch();
	$stmt->closeCursor();

	// RANK COMMAND SYSTEM
	$dptinf = json_decode($dp['info'], true);
	if(intval($res['rank']) >= intval($dptinf['cmdrank']) && $permname == "pdcmd") return true;
	
	// MERGE PERMISSION ARRAYS FROM DEPT AND USERS TO CREATE ONE PERMISSION ARRAY, SEARCH FOR PERMISSION IN MERGED ARRAY
	$dperms = json_decode($dp['perms']);
	$uperms = json_decode($res['plevel']);
	$perms = array_merge($uperms, $dperms);
	if(in_array("all", $perms)) return true;
	if(in_array($permname, $perms)) return true;
	return false;
}

function getRequests($uid = 0) {
	global $pdo;
	if(!$uid) {
		$stmt = $pdo->prepare("SELECT * FROM `requests`");
		$stmt->execute();
	} else {
		$stmt = $pdo->prepare("SELECT * FROM `requests` WHERE `uid` = :uid");
		$stmt->bindParam(":uid", $uid);
		$stmt->execute();
	}
	return $stmt->fetchAll();
}

function createRequest($type, $value) {
	global $pdo;
	$usr = getUser($_SESSION['uid'], U_ID);
	$req = Array("type" => $type, "value" => $value);
	$reqjson = json_encode($req);
	$stmt = $pdo->prepare("INSERT INTO `requests` (`data`, `uid`) VALUES (:req, :uid)");
	$stmt->bindParam(":req", $reqjson);
	$stmt->bindParam(":uid", $usr['id']);
	$stmt->execute();
}

function deleteRequest($rid) {
	global $pdo;
	$stmt = $pdo->prepare("DELETE FROM `requests` WHERE `id` = :rid LIMIT 1");
	$stmt->bindParam(":rid", $rid);
	$stmt->execute();
	return $stmt->rowCount();
}

function processRequest($rid) {
	global $pdo;
	$stmt = $pdo->prepare("SELECT * FROM `requests` WHERE `id` = :rid");
	$stmt->bindParam(":rid", $rid);
	$stmt->execute();
	if(!$stmt->rowCount()) return false;
	$res = $stmt->fetch();
	$rjs = json_decode($res['data'], true);
	$rc = 0;
	switch($rjs['type']) {
		case "dept":
		$fdpt = getDeptName($res['uid']);
		$stmt = $pdo->prepare("UPDATE `users` SET `dept` = :value WHERE `id` = :uid");
		$stmt->bindParam(":value", $rjs['value']);
		$stmt->bindParam(":uid", $res['uid']);
		$stmt->execute();
		$rc = $stmt->rowCount();
		$dpt = getDept($rjs['value']);
		/*logAction(null, $res['uid'], L_TRANS, json_encode(Array($fdpt, $dpt['dname'])));*/
		break;
		case "name":
		$rusr = getUser($res['uid'], U_ID);
		$stmt = $pdo->prepare("UPDATE `users` SET `display` = :value WHERE `id` = :uid");
		$stmt->bindParam(":value", $rjs['value']);
		$stmt->bindParam(":uid", $res['uid']);
		$stmt->execute();
		$rc = $stmt->rowCount();
		/*logAction(null, $res['uid'], L_NAME, json_encode(Array($rusr['display'], $rjs['value'])));*/
		break;
		default: return false;
	}
	$stmt->closeCursor();
	if($rc) {
		$stmt = $pdo->prepare("DELETE FROM `requests` WHERE `id` = :rid LIMIT 1");
		$stmt->bindParam(":rid", $rid);
		$stmt->execute();
	}
	return $rc;
}

/**
 * Generate random salt
 */
function genSalt(int $length = 10): string {
    return bin2hex(random_bytes($length));
}

/**
 * Hash password with salt
 */
function hashPass(string $pass, string $salt): string {
    return hash('sha256', $pass . $salt);
}

function getCiv($name, $method = U_DNAME) {
	global $pdo;
	$mthd = null;
	switch($method) {
		case U_DNAME:
			$mthd = "name";
		break;
		case U_ID:
			$mthd = "id";
		break;
		default: return false;
	}
	$stmt = $pdo->prepare("SELECT * FROM `civs` WHERE `$mthd` = :name");
	$stmt->bindParam(":name", $name);
	$stmt->execute();
	if($stmt->rowCount())
		return $stmt->fetch();
	return false;
}

function createCiv($name) {
	if(getCiv($name)) return false;
	global $pdo;
	$stmt = $pdo->prepare("INSERT INTO `civs` (`name`) VALUES (:name)");
	$stmt->bindParam(":name", $name);
	$stmt->execute();
	if($stmt->rowCount()) {
		$stmt->closeCursor();
		return getCiv($name);
	} else return false;
}

// Case 0 = List all records for specific person that are not expunged
// Case 1 = List only records for specific person not processed by DOC and are not expunged
// Case 2 = List only specific record for specific person
// Case 3 = List only records for specific person that are expunged
// Case 4 = List ALL records for specific person reguardless of status
function getArrests($crid,$q=0) {
	global $pdo;
	switch ($q){
		case 0: $stmt = $pdo->prepare("SELECT * FROM `arrests` WHERE `uid` = :crid AND `exp` = 0 ORDER BY `id` DESC"); break;
		case 1: $stmt = $pdo->prepare("SELECT * FROM `arrests` WHERE `uid` = :crid AND `exp` = 0 AND `proc` = 0 ORDER BY `id` DESC"); break;
		case 2: $stmt = $pdo->prepare("SELECT * FROM `arrests` WHERE `id` = :crid ORDER BY `id` DESC"); break;
		case 3: $stmt = $pdo->prepare("SELECT * FROM `arrests` WHERE `uid` = :crid AND `exp` != 0 ORDER BY `id` DESC"); break;
		case 4: $stmt = $pdo->prepare("SELECT * FROM `arrests` WHERE `uid` = :crid ORDER BY `id` DESC"); break;
	}
	$stmt->bindParam(":crid", $crid);
	$stmt->execute(); 
	if(!$stmt->rowCount()) return false;
	return $stmt->fetchAll();
}

// Case 0 = List all records for specific person that are not expunged
function getWarrants($crid,$q=0) {
	global $pdo;
	switch ($q){
		case 0: $stmt = $pdo->prepare("SELECT * FROM `warrants` WHERE `uid` = :crid AND `active` = 0 ORDER BY `id` DESC"); break;
	}
	$stmt->bindParam(":crid", $crid);
	$stmt->execute(); 
	if(!$stmt->rowCount()) return false;
	return $stmt->fetchAll();
}

function getBolos($histLimit, $active = false) {
	global $pdo;
	$format = "Y-m-d H:i:s";
	$sec = $histLimit * 3600;
	$lapsed = gmdate($format, time() - $sec);
	if($active == true){
		$stmt = $pdo->prepare("SELECT * FROM `bolo` WHERE `RealDate` >= :lapsed AND `canceled` = '0' ORDER BY `id` DESC");
	}else{
		$stmt = $pdo->prepare("SELECT * FROM `bolo` WHERE `RealDate` >= :lapsed ORDER BY `id` DESC");
	}
	$stmt->bindParam(":lapsed", $lapsed);
	$stmt->execute();
	if(!$stmt->rowCount()) return false;
	return $stmt->fetchAll();
}

function getTraffic($trac) {
	global $pdo;
	$stmt = $pdo->prepare("SELECT * FROM `traffic` WHERE `civid` = :trac ORDER BY `id` DESC");
	$stmt->bindParam(":trac", $trac);
	$stmt->execute();
	if(!$stmt->rowCount()) return false;
	return $stmt->fetchAll();
}

// * ACCEPTS U_UNAME, U_DNAME, OR U_ID ACCORDINGLY DEPENDING ON WANTED CRITERIA
function getUser($criteria, $method = U_DNAME) {
	global $pdo;
	$mthd = null;
	
	switch($method) {
		case U_DNAME:
			$mthd = "display";
		break;
		case U_UNAME:
			$mthd = "uname";
		break;
		case U_ID:
			$mthd = "id";
		break;
		default: return false;
	}
	$stmt = $pdo->prepare("SELECT * FROM `users` WHERE `$mthd` = :crit");
	$stmt->bindParam(":crit", $criteria);
	$stmt->execute();
	if($stmt->rowCount()) return $stmt->fetch();
	return false;
}

function newBond($crid, $cdate, $amt) {
	global $pdo;
	$stmt = $pdo->prepare("INSERT INTO `bonds` (`citid` ,`cdate` ,`bondamnt` ,`resolved`) VALUES (:crid, :cdate, :amt, '0')");
	$stmt->bindParam(":crid", $crid);
	$stmt->bindParam(":cdate", $cdate);
	$stmt->bindParam(":amt", $amt);
	$stmt->execute();
	$stmt->closeCursor();
	$stmt = $pdo->prepare("SELECT `id` FROM `bonds` WHERE `citid` = :citid ORDER BY `id` DESC");
	$stmt->bindParam(":citid", $crid);
	$stmt->execute();
	$bid = $stmt->fetch();
	return $bid['id'];
}

function newArrest($crid, $crimes, $evd, $time, $date, $bailbond, $bail) {
	global $pdo;
	$bid = -1;
	if($bailbond == "Bond") {
		$bid = newBond($crid, '2099-01-01', $bail);
		$bail = 0;
	}
	$cop = getUser($_SESSION['uid'], U_ID);
	$stmt = $pdo->prepare("INSERT INTO `arrests` (`uid` ,`copid` ,`docid` ,`date` ,`time` ,`bondid` ,`proc` ,`crimes` ,`evd` ,`bail` ,`plea` ,`exp` ,`dojid` ,`RealDate`) VALUES (:uid, :copid, '0', :date, :time, :bondid, '0', :crimes, :evd, :bail, '0', '0', '0', UTC_TIMESTAMP())");
	$stmt->bindParam(":uid", $crid);
	$stmt->bindParam(":copid", $cop['id']);
	$stmt->bindParam(":date", $date);
	$stmt->bindParam(":time", $time);
	$stmt->bindParam(":bondid", $bid);
	$stmt->bindParam(":crimes", $crimes);
	$stmt->bindParam(":evd", $evd);
	$stmt->bindParam(":bail", $bail);
	$stmt->execute();
	$stmt->closeCursor();
	$stmt = $pdo->prepare("SELECT `id` FROM `arrests` WHERE `uid` = :id ORDER BY `id` DESC");
	$stmt->bindParam(":id", $crid);
	$stmt->execute();
	$arrinfo = $stmt->fetch();
	$stmt->closeCursor();
	return $arrinfo;
}

function newWarrant($crid, $dojname, $warrant, $wtype, $date, $wlink) {
	global $pdo;
	$cop = getUser($_SESSION['uid'], U_ID);
	$stmt = $pdo->prepare("INSERT INTO `warrants` (`uid` ,`copid` ,`dojname` ,`date` ,`crimes` ,`wtype` ,`wlink` ,`active` ,`RealDate`) VALUES (:uid, :copid, :dojname, :date, :crimes, :wtype, :wlink, '0', UTC_TIMESTAMP())");
	$stmt->bindParam(":uid", $crid);
	$stmt->bindParam(":copid", $cop['id']);
	$stmt->bindParam(":dojname", $dojname);
	$stmt->bindParam(":date", $date);
	$stmt->bindParam(":crimes", $warrant);
	$stmt->bindParam(":wtype", $wtype);
	$stmt->bindParam(":wlink", $wlink);
	$stmt->execute();
	$stmt->closeCursor();
	$stmt = $pdo->prepare("SELECT `id` FROM `warrants` WHERE `uid` = :id ORDER BY `id` DESC");
	$stmt->bindParam(":id", $crid);
	$stmt->execute();
	$stmt->closeCursor();
}

function newIntake($crid) {
	global $pdo;
	$cop = getUser($_SESSION['uid'], U_ID);
	$stmt = $pdo->prepare("UPDATE `arrests` SET `docid` = :copid, `proc` = '1' WHERE `id` = :id");
	$stmt->bindParam(":id", $crid);
	$stmt->bindParam(":copid", $cop['id']);
	$stmt->execute();
}

function newBolo($info) {
	global $pdo;
	$cop = getUser($_SESSION['uid'], U_ID);
	$stmt = $pdo->prepare("INSERT INTO `bolo` (`copid` ,`canceled` ,`info` ,`RealDate`) VALUES (:copid, '0', :info, UTC_TIMESTAMP())");
	$stmt->bindParam(":copid", $cop['id']);
	$stmt->bindParam(":info", $info);
	$stmt->execute();
	$stmt->closeCursor();
	$stmt = $pdo->prepare("SELECT `id` FROM `bolo` WHERE `info` = :info ORDER BY `id` DESC");
	$stmt->bindParam(":info", $info);
	$stmt->execute();
	$arrinfo = $stmt->fetch();
	$stmt->closeCursor();
	return $arrinfo;
}

function cancelBolo($boid) {
	global $pdo;
	$doj = getUser($_SESSION['uid'], U_ID);
	$stmt = $pdo->prepare("UPDATE `bolo` SET `canceled` = :dojid WHERE `id` = :id");
	$stmt->bindParam(":id", $boid);
	$stmt->bindParam(":dojid", $doj['id']);
	$stmt->execute();
}

function newTraffic($trac, $reason, $date, $ticket, $notes) {
	global $pdo;
	$tid = -1;
	$cop = getUser($_SESSION['uid'], U_ID);
	$stmt = $pdo->prepare("INSERT INTO `traffic` (`civid` ,`copid` ,`date` ,`reason` ,`ticket` ,`notes` ,`RealDate`) VALUES (:civid, :copid, :date, :reason, :ticket, :notes, UTC_TIMESTAMP())");
	$stmt->bindParam(":civid", $trac);
	$stmt->bindParam(":copid", $cop['id']);
	$stmt->bindParam(":date", $date);
	$stmt->bindParam(":reason", $reason);
	$stmt->bindParam(":ticket", $ticket);
	$stmt->bindParam(":notes", $notes);
	$stmt->execute();
	$stmt->closeCursor();
	$stmt = $pdo->prepare("SELECT `id` FROM `traffic` WHERE `civid` = :id ORDER BY `id` DESC");
	$stmt->bindParam(":id", $trac);
	$stmt->execute();
	$trainfo = $stmt->fetch();
	$stmt->closeCursor();
	return $trainfo;
}

function updateExpunged($arid) {
	global $pdo;
	$cop = getUser($_SESSION['uid'], U_ID);
	$me = $_SESSION['uid'];
	$currentDate = date("Y-m-d");
	$stmt = $pdo->prepare("UPDATE `arrests` SET `exp` = $me, `dojid` = :dojid, `date` = :date WHERE `id` = :id");
	$stmt->bindParam(":id", $arid);
	$stmt->bindParam(":date", $currentDate);
	$stmt->bindParam(":dojid", $cop['id']);
	$stmt->execute();
}

function updateWarrant($arid) {
	global $pdo;
	$cop = getUser($_SESSION['uid'], U_ID);
	$me = $_SESSION['uid'];
	$stmt = $pdo->prepare("UPDATE `warrants` SET `active` = 1 WHERE `id` = :id");
	$stmt->bindParam(":id", $arid);
	$stmt->execute();
}

/*
* REGISTRATION RETURN VALUES
* false = SUCCESS
* 1 = DUPLICATE USERNAME
* 2 = DUPLICATE DISPLAY NAME(RP NAME)
* 3 = DUPLICATE EMAIL
* 4 = QUERY ERROR
*/ 
function regUser($uname, $disname, $pass, $email) {
	global $pdo;
	
	$salt = genSalt();
	$phash = hashPass($pass, $salt);
	$stmt = $pdo->prepare("SELECT * FROM `users` WHERE `display` = :name OR `uname` = :uname OR `email` = :email");
	
	$civid = getCiv($disname);
	if(!$civid) $civid = createCiv($disname);
	
	$stmt->bindParam(":name", $disname);
	$stmt->bindParam(":uname", $uname);
	$stmt->bindParam(":email", $email);
	$stmt->execute();
	if($stmt->rowCount()) {
		$user = $stmt->fetch();
		if($user['uname'] == $uname) return 1;
		if($user['display'] == $disname) return 2;
		if($user['email'] == $email) return 3;
	}
	$stmt->closeCursor();
	$stmt = $pdo->prepare("INSERT INTO `users` (`citid`, `RegiDate`, `LastLogin`, `uname`, `display`, `phash`, `salt`, `ip`, `email`, `plevel`) VALUES (:civid, NOW(), NOW(), :uname, :disname, :phash, :psalt, '$_SERVER[REMOTE_ADDR]', :email, '[\"none\"]')");
	$stmt->bindParam(":civid", $civid['id']);
	$stmt->bindParam(":uname", $uname);
	$stmt->bindParam(":disname", $disname);
	$stmt->bindParam(":phash", $phash);
	$stmt->bindParam(":psalt", $salt);
	$stmt->bindParam(":email", $email);
	$stmt->execute();
	if($stmt->rowCount()) return false;
	return 4;
}

/**
 * Logout user
 */
function logout(): void {
    if (isset($_COOKIE['r'])) {
        $pdo = getDB();
        $stmt = $pdo->prepare("DELETE FROM remember WHERE hash = :hash");
        $hash = hash("sha256", $_COOKIE['r']);
        $stmt->bindParam(":hash", $hash);
        $stmt->execute();
        
        setcookie("r", "", time() - 3600, '/', '', true, true);
    }
    
    if (is_session_started()) {
        $_SESSION = array();
        session_destroy();
    }
}

function setUData($newVal, $type = -1, $uid = 0) {
	global $pdo;
	if(!$uid) $uid = $_SESSION['uid'];
	$dtype = NULL;
	$stmt = 0;
	switch($type) {
		case U_PASS:
		$salt = genSalt();
		$pass = hashPass($newVal, $salt);
		$stmt = $pdo->prepare("UPDATE `users` SET `phash` = :pass, `salt` = :salt WHERE `id` = :uid");
		$stmt->bindParam(":pass", $pass);
		$stmt->bindParam(":salt", $salt);
		$stmt->bindParam(":uid", $uid);
		$stmt->execute();
		break;
		case U_DNAME:
		$dtype = "display";
		break;
		case U_PHONE:
		$dtype = "phone";
		break;
		case U_BADGE:
		$dtype = "badge";
		break;
		case U_UNAME:
		$dtype = "uname";
		break;
		default: return false;
	}
	if($dtype != NULL) {
		$stmt = $pdo->prepare("UPDATE `users` SET `$dtype` = :newVal WHERE `id` = :uid");
		$stmt->bindParam(":uid", $uid);
		$stmt->bindParam(":newVal", $newVal);
		$stmt->execute();
	}
	return $stmt->rowCount();
}

function getDepts($auth = 35, $inorder = false, $section = 0) {
	global $pdo;
	$stmt = NULL;
	$ostr = " ORDER BY `authority` DESC";
	if($inorder) $ostr = " ORDER BY `id` ASC";
	$stmt = $pdo->prepare("SELECT * FROM `dept` WHERE `authority` < $auth AND `section` = 0 OR `section` = 2".$ostr);
	$stmt->execute();
	return $stmt->fetchAll();
}

function getDept($dept) {
	global $pdo;
	$stmt = $pdo->prepare("SELECT * FROM `dept` WHERE `id` = '$dept' AND `section` = 0 OR `section` = 2 ORDER BY `authority` DESC");
	$stmt->execute();
	return $stmt->fetch();
}

function getRankName($uid) {
	global $pdo;
	$stmt = $pdo->prepare("SELECT `dept`,`rank` FROM `users` WHERE `id` = :uid");
	$stmt->bindParam(":uid", $uid);
	$stmt->execute();
	if(!$stmt->rowCount()) return false;
	$ur = $stmt->fetch();
	$stmt->closeCursor();
	$depts = getDept($ur['dept']);
	$ranks = json_decode($depts['ranks']);
	return $ranks[$ur['rank']];
}

function getDeptRanks($dept) {
	global $pdo;
	$stmt = $pdo->prepare("SELECT `rank` FROM `users` WHERE `id` = :dept ORDER BY `authority` DESC");
	$stmt->bindParam(":dept", $dept);
	$stmt->execute();
	if(!$stmt->rowCount()) return false;
	return $stmt->fetch();
}

function getDeptName($uid) {
	global $pdo;
	$stmt = $pdo->prepare("SELECT `dept` FROM `users` WHERE `id` = :uid");
	$stmt->bindParam(":uid", $uid);
	$stmt->execute();
	if(!$stmt->rowCount()) return false;
	$ur = $stmt->fetch();
	$stmt->closeCursor();
	$depts = getDept($ur['dept']);
	return $depts['dname'];
}

function verifyUser($uid, $action = 0, $dept = 1, $rank = 0) {
	global $pdo;
	switch($action) {
		case 0: return false;
		case 2:
		$dept = TERM_ID;
		$rank = TERM_ID;
		break;
		default:
		break;
	}
	$user = getUser($uid, U_ID);
	if($user['dept'] != -1) return false;
	$stmt = $pdo->prepare("UPDATE `users` SET `rank` = :rank, `dept` = :dept WHERE `id` = :uid");
	$stmt->bindParam(":uid", $uid);
	$stmt->bindParam(":rank", $rank);
	$stmt->bindParam(":dept", $dept);
	$stmt->execute();
	return $stmt->rowCount();
}

function copsByDept($dept) {
	global $pdo;
	$stmt = $pdo->prepare("SELECT `id`, `rank`, `display`, `badge`, `LastLogin` FROM `users` WHERE `dept` = :dept ORDER BY `rank` DESC");
	$stmt->bindParam(":dept", $dept);
	$stmt->execute();
	if(!$stmt->rowCount()) return false;
	return $stmt->fetchAll();
}

function titleFormat($str) {
	$str = ucwords($str);
	return str_replace(Array(" Of ", " A ", " In ", " An ", " To ", " On "), Array(" of ", " a ", " in ", " an ", " to ", " on "), $str);
}

/**
 * Get system information
 * 
 * @param string $name
 * @return array|null
 */
function getInfo(string $name): ?array {
    try {
        $pdo = getDB();
        $stmt = $pdo->prepare("SELECT * FROM info WHERE name = :name");
        $stmt->bindParam(":name", $name);
        $stmt->execute();
        return $stmt->fetch() ?: null;
    } catch (PDOException $e) {
        error_log("Failed to get info: " . $e->getMessage());
        return null;
    }
}

/**
 * Update system information
 * 
 * @param string $name
 * @param string $data
 * @return bool
 */
function updateInfo(string $name, string $data): bool {
    try {
        $pdo = getDB();
        $stmt = $pdo->prepare("UPDATE info SET data = :data WHERE name = :name");
        $stmt->bindParam(":name", $name);
        $stmt->bindParam(":data", $data);
        return $stmt->execute();
    } catch (PDOException $e) {
        error_log("Failed to update info: " . $e->getMessage());
        return false;
    }
}

function fireMember($uid, $log = true) {
	global $pdo;
	/*if($log) logAction($_SESSION['uid'], $uid, L_TERM, getDeptName($uid));*/
	$stmt = $pdo->prepare("UPDATE `users` SET `dept` = '".TERM_ID."', `rank` = '".TERM_ID."' WHERE `id` = :id");
	$stmt->bindParam(":id", $uid);
	$stmt->execute();
	return $stmt->rowCount();
}

function setRank($uid, $nrank, $log = true) {
	global $pdo;
	$stmt = $pdo->prepare("UPDATE `users` SET `rank` = :nrank WHERE `id` = :uid");
	$stmt->bindParam(":uid", $uid);
	$stmt->bindParam(":nrank", $nrank);
	$stmt->execute();
	return $stmt->rowCount();
}

function isSubOf($d1, $d2) {
	global $pdo;
	$stmt = $pdo->prepare("SELECT `info` FROM `dept` WHERE `id` = :d1");
	$stmt->bindParam(":d1", $d1);
	$stmt->execute();
	if(!$stmt->rowCount()) return false;
	$res = $stmt->fetch();
	$subs = json_decode($res['info'], true);
	return in_array(intval($d2), $subs['reporters']);
}

function sCiv($id) {
	global $pdo;
	$id = intval($id);
	$pdo->exec("UPDATE `civs` SET `scount` = `scount` + 1 WHERE `id` = '$id'");
	return;
}

function autoComp($inp, $id, $del = 1000) {
	$acn = genSalt(10);
	$dl = genSalt(10);
	$lv = genSalt(10);
	echo "<script type=\"text/javascript\">
var $lv = \"\";
function $acn() {
	var cVal = document.getElementById(\"$id\").value;
	if(cVal.length >= 2 && $lv != cVal) {
		$.get( \"autocomplete.php?name=\"+document.getElementById(\"$id\").value, function( data ) {
			document.getElementById(\"$acn\").innerHTML = data;
		});
		$lv = cVal;
	}
}
setInterval(\"$acn()\", $del);
</script>
<input autocomplete=\"off\" type=\"text\" list=\"$acn\" id=\"$id\" class=\"form-control\" name=\"$inp\">
<datalist id=\"$acn\"></datalist>";
}

function isCop($scrit, $sval = U_DNAME) {
	$cop = getUser($scrit, $sval);
	if(!$cop) return false;
	if($cop['dept'] == TERM_ID || $cop['dept'] == PENDING) return false;
	return true;
}

// Check if IP changed during session
if (isLoggedIn() && $_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
    logout();
}

/**
 * Check if session is started
 */
function is_session_started(): bool {
    if (php_sapi_name() !== 'cli') {
        if (version_compare(phpversion(), '5.4.0', '>=')) {
            return session_status() === PHP_SESSION_ACTIVE;
        }
        return session_id() !== '';
    }
    return false;
}

/**
 * Sanitize input data
 */
function sanitizeInput(string $data): string {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

/**
 * Generate CSRF token
 */
function generateCSRFToken(): string {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token
 */
function verifyCSRFToken(string $token): bool {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Set system information
 * 
 * @param string $key The key to set
 * @param string $value The value to set
 * @return bool Whether the operation was successful
 */
function setInfo(string $key, string $value): bool {
    try {
        $pdo = getDB();
        $stmt = $pdo->prepare("INSERT INTO system_info (key, data) VALUES (:key, :value) ON DUPLICATE KEY UPDATE data = :value");
        $stmt->bindParam(":key", $key);
        $stmt->bindParam(":value", $value);
        return $stmt->execute();
    } catch (PDOException $e) {
        error_log("Failed to set system info: " . $e->getMessage());
        return false;
    }
}
?>
