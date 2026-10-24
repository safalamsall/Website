<?php
// VULNERABILITY: phpinfo() exposed — information disclosure
// Reveals PHP version, loaded modules, server paths, env vars, etc.
// Real attackers look for this file via directory brute-force
phpinfo();
?>
