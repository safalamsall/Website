<?php
header('Content-Type: image/svg+xml');
echo '<svg xmlns="http://www.w3.org/2000/svg" width="300" height="220">
  <rect width="300" height="220" fill="#f1f5f9"/>
  <rect x="90" y="60" width="120" height="80" rx="8" fill="#e2e8f0"/>
  <circle cx="150" cy="80" r="20" fill="#cbd5e1"/>
  <text x="150" y="175" text-anchor="middle" font-family="sans-serif" font-size="13" fill="#94a3b8">No Image</text>
</svg>';
?>
