<?php
declare(strict_types=1);

require_once("php_includes/base.inc.php");

// Get user timezone
$usrTZ = filter_input(INPUT_COOKIE, "LSTZ", FILTER_SANITIZE_STRING) ?: "UTC";

try {
	// Get threat level
	$tinfo = getInfo("threat");
	$tinfo = json_decode($tinfo['data'] ?? '{}', true);
	$t = intval($tinfo['level'] ?? 0);

	// Set threat level color
	$col = match($t) {
		1 => "<span style=\"color: #00aa00; font-weight: bold\">GREEN</span>",
		2 => "<span style=\"color: #ffaa00; font-weight: bold\">AMBER</span>",
		3 => "<span style=\"color: red; font-weight: bold\">RED</span>",
		4 => "<span style=\"color: maroon; font-weight: bold\">DEEP RED</span>",
		5 => "<span style=\"color: black; font-weight: bold\" id=\"mlaw\">MARTIAL LAW</span>",
		default => "<span style=\"color: white; font-weight: bold\">UNKNOWN</span>"
	};

	// Get active BOLOs
	$tickerLimit = "1";
	$onlyActive = true;
	$boloTicker = getBolos($tickerLimit, $onlyActive);

	if ($boloTicker) {
		$btformat = "H:i:s";
		$btcnt = count($boloTicker);
?>
<div id="boloContainer" role="complementary" aria-label="Active BOLOs">
	<div id="boloTicker">
		<ul id="boloFeed">
			<li><b><?php echo $btcnt; ?> Active Bolos Past Hour:</b></li>
			<?php
			for ($i = 0; $i < $btcnt; $i++) {
				$item = "item" . $i;
				$btutcTS = antiXSS($boloTicker[$i]['RealDate']);
				$usrTS = date_create($btutcTS, new DateTimeZone("UTC"))
					->setTimeZone(new DateTimeZone($usrTZ))
					->format($btformat);
				$divider = ($i == $btcnt - 1) ? "<b></b>" : "<b>|</b>";
				echo "<li id='" . $item . "'><i>" . $usrTS . "</i>" . titleFormat(antiXSS($boloTicker[$i]['info'])) . $divider . "</li>\n";
			}
			?>
		</ul>
	</div>
</div>
<?php
	}
} catch (Exception $e) {
	error_log("Error in boloTicker.php: " . $e->getMessage());
}
?>

<?php if ($t === 5): ?>
<script>
document.addEventListener('DOMContentLoaded', function() {
	const mlaw = document.getElementById('mlaw');
	if (mlaw) {
		setInterval(() => {
			mlaw.style.opacity = mlaw.style.opacity === '0.0' ? '1.0' : '0.0';
		}, 250);
	}
});
</script>
<?php endif; ?>

