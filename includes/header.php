<?php
// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once __DIR__ . '/db.php';

// Get cart count for logged-in user
$cart_count = 0;
if (isset($_SESSION['user_id'])) {
    $uid = $_SESSION['user_id'];
    // VULNERABILITY: user_id from session injected directly
    $cart_row = db_fetch_one("SELECT SUM(quantity) as cnt FROM cart WHERE user_id = $uid");
    $cart_count = $cart_row ? (int)$cart_row['cnt'] : 0;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnShop - <?php echo isset($page_title) ? $page_title : 'Online Store'; ?></title>
    <link rel="stylesheet" href="/vuln-shop/css/style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>

<!-- Top bar -->
<div class="topbar">
    <div class="container">
        <span><i class="fas fa-phone"></i> +1 (555) 000-VULN</span>
        <span><i class="fas fa-envelope"></i> support@vulnshop.com</span>
        <span class="topbar-right">
            <?php if (isset($_SESSION['user_id'])): ?>
                Welcome, <strong><?php echo $_SESSION['username']; /* XSS: no escaping */ ?></strong> |
                <a href="/vuln-shop/profile.php">My Account</a> |
                <a href="/vuln-shop/logout.php">Logout</a>
            <?php else: ?>
                <a href="/vuln-shop/login.php">Login</a> |
                <a href="/vuln-shop/register.php">Register</a>
            <?php endif; ?>
        </span>
    </div>
</div>

<!-- Main navbar -->
<nav class="navbar">
    <div class="container nav-inner">
        <a href="/vuln-shop/index.php" class="logo">
            <i class="fas fa-shopping-bag"></i> Vuln<span>Shop</span>
        </a>

        <div class="nav-search">
            <!-- VULNERABILITY: search term reflected without escaping -->
            <form action="/vuln-shop/search.php" method="GET">
                <input type="text" name="q"
                       placeholder="Search products..."
                       value="<?php echo isset($_GET['q']) ? $_GET['q'] : ''; ?>">
                <button type="submit"><i class="fas fa-search"></i></button>
            </form>
        </div>

        <div class="nav-links">
            <a href="/vuln-shop/index.php"><i class="fas fa-home"></i> Home</a>
            <a href="/vuln-shop/search.php"><i class="fas fa-th"></i> Products</a>
            <a href="/vuln-shop/cart.php">
                <i class="fas fa-shopping-cart"></i> Cart
                <?php if ($cart_count > 0): ?>
                    <span class="cart-badge"><?php echo $cart_count; ?></span>
                <?php endif; ?>
            </a>
            <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
                <a href="/vuln-shop/admin/index.php" class="admin-link"><i class="fas fa-cog"></i> Admin</a>
            <?php endif; ?>
        </div>
    </div>
</nav>

<!-- Flash messages -->
<?php if (isset($_SESSION['flash_msg'])): ?>
    <div class="flash-msg flash-<?php echo $_SESSION['flash_type'] ?? 'info'; ?>">
        <div class="container">
            <!-- VULNERABILITY: flash message output without escaping -->
            <?php echo $_SESSION['flash_msg']; unset($_SESSION['flash_msg']); unset($_SESSION['flash_type']); ?>
        </div>
    </div>
<?php endif; ?>

<main class="container main-content">
