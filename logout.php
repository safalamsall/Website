<?php
// Simple logout - no CSRF protection (CSRF logout attack possible)
session_start();
session_destroy();
header('Location: /vuln-shop/login.php');
exit;
?>
