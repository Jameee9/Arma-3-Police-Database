<?php
declare(strict_types=1);

require_once("php_includes/base.inc.php");

// Get user permissions
$off = hasPerm("officer");
$dev = hasPerm("all");
$cmd = hasPerm("pdcmd");
$dtu = hasPerm("dtu");
?>
<div id="sidebar" role="complementary">

				<!-- Widget Area -->
				<div id="widgets">
				
					<!-- Main menu -->
					<nav id="mainmenu" role="navigation" aria-label="Main menu">
						<ul>
							<?php if (isLoggedIn()): ?>
							<li><a href="index.php" class="active" aria-current="page">Home</a></li><?php else: ?>
							<li><a href="login.php" class="active" aria-current="page">Login</a></li><?php endif; ?>
							<?php
							if($off) {
							?>
                            <li><a href="addBolo.php">BOLO Dashboard</a></li>
                            <li><a href="freq.php">Frequencies & Threat</a></li>
                            <li>
                            	<a href="#" aria-haspopup="true">Records</a>
                            	<ul aria-label="Records submenu">
                            		<li><a href="crime.php">Criminal Database</a></li>
                                    <li><a href="traffic.php">Infractions</a></li>
                                    <li><a href="doc.php">DOC Panel</a></li>
                                    <?php if(hasPerm("doj")) { ?>
                                    <li><a href="expungement.php">Expungements</a></li>
                                    <?php } ?>
                                </ul>
                            </li>
                            <?php
                            }
							if($off) {
							?>
                            <li>
                            	<a href="#" aria-haspopup="true">Useful Information</a>
                            	<ul aria-label="Useful Information submenu">
                            		<li><a href="roster.php">Police Roster</a></li>
                                	<li><a href="arrests.php">Recent Arrests</a></li>
                                	<li><a href="citations.php">Recent Citations</a></li>
                                	<li><a href="info.php">Useful Links</a></li>
                                </ul>
                            </li>
							<li>
                            	<a href="#" aria-haspopup="true">Warrants</a>
                            	<ul aria-label="Warrants submenu">
                            		<li><a href="wname.php">Search/Add Warrants</a></li>
                                	<li><a href="warrants.php">View All Warrants</a></li>
                                </ul>
                            </li>
							<?php
                            }
							if($off && $cmd) {
							?>
							<li>
                            	<a href="#" aria-haspopup="true">Command Tools</a>
                            	<ul aria-label="Command Tools submenu">
                            		<li><a href="dashboard.php">Dashboard</a></li>
                                	<li><a href="verify.php">User Requests</a></li>
                                	<li><a href="control.php">Officer Management</a></li>
                                </ul>
                            </li>
                            <?php
                            }
							if($dev) {
							?>
							<li>
                            	<a href="#" aria-haspopup="true">Admin Tools</a>
                            	<ul aria-label="Admin Tools submenu">
                            		<li><a href="admin.php">Database Settings</a></li>
                            		<li><a href="all.php">All Arrests</a></li>
                            		<li><a href="passhasher.php">Password Hasher</a></li>
                                </ul>
                            </li>
							<?php
							}
							?>
							<?php if(isLoggedIn()) { ?>
                            <li><a href="settings.php">User Settings</a></li>
                            <li><a href="changes.php">Changelog</a></li>
                            <li><a href="logout.php">Logout</a></li><?php } ?>
						</ul>
					</nav>

				</div>