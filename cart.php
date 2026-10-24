<?php
// ============================================================
//  VulnShop - Shopping Cart
//  VULNERABILITIES:
//  - CSRF: add/remove/update cart actions have no CSRF tokens
//  - SQLi: product_id and quantity injected raw
//  - No ownership check when removing items (IDOR)
//  - Negative quantity accepted (price manipulation)
// ============================================================
$page_title = 'Shopping Cart';
require_once 'includes/header.php';

// Ensure user is logged in (weakly enforced)
if (!isset($_SESSION['user_id'])) {
    $_SESSION['flash_msg']  = 'Please login to use your cart.';
    $_SESSION['flash_type'] = 'warning';
    header('Location: /vuln-shop/login.php');
    exit;
}

$user_id = $_SESSION['user_id'];

// --- Handle Actions ---

// Add to cart via GET (CSRF-able via image tag: <img src="/vuln-shop/cart.php?action=add&product_id=1">)
if (isset($_GET['action']) && $_GET['action'] === 'add') {
    // VULNERABILITY: product_id raw in SQL
    $product_id = $_GET['product_id'];
    $qty        = isset($_GET['qty']) ? $_GET['qty'] : 1;

    $exists = db_fetch_one("SELECT id, quantity FROM cart
                            WHERE user_id = $user_id AND product_id = $product_id");
    if ($exists) {
        db_query("UPDATE cart SET quantity = quantity + $qty
                  WHERE user_id = $user_id AND product_id = $product_id");
    } else {
        db_query("INSERT INTO cart (user_id, product_id, quantity)
                  VALUES ($user_id, $product_id, $qty)");
    }
    $_SESSION['flash_msg']  = 'Item added to cart!';
    $_SESSION['flash_type'] = 'success';
    $ref = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '/vuln-shop/index.php';
    header("Location: $ref");
    exit;
}

// Add to cart via POST (from product page)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_to_cart'])) {
    // VULNERABILITY: raw values in SQL, no CSRF token checked
    $product_id = $_POST['product_id'];
    $qty        = $_POST['quantity'];

    $exists = db_fetch_one("SELECT id, quantity FROM cart
                            WHERE user_id = $user_id AND product_id = $product_id");
    if ($exists) {
        db_query("UPDATE cart SET quantity = quantity + $qty
                  WHERE user_id = $user_id AND product_id = $product_id");
    } else {
        db_query("INSERT INTO cart (user_id, product_id, quantity)
                  VALUES ($user_id, $product_id, $qty)");
    }
    $_SESSION['flash_msg']  = 'Item added to cart!';
    $_SESSION['flash_type'] = 'success';
    header('Location: /vuln-shop/cart.php');
    exit;
}

// Remove item — VULNERABILITY: no ownership verification (IDOR)
if (isset($_GET['action']) && $_GET['action'] === 'remove') {
    $cart_id = $_GET['cart_id'];
    // VULNERABILITY: any logged-in user can remove any cart item by ID
    db_query("DELETE FROM cart WHERE id = $cart_id");
    $_SESSION['flash_msg']  = 'Item removed.';
    $_SESSION['flash_type'] = 'info';
    header('Location: /vuln-shop/cart.php');
    exit;
}

// Update quantity — VULNERABILITY: negative qty accepted = negative total
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_cart'])) {
    foreach ($_POST['quantities'] as $cart_id => $qty) {
        // VULNERABILITY: $qty can be negative, 0 or non-numeric
        if ((int)$qty <= 0) {
            db_query("DELETE FROM cart WHERE id = $cart_id AND user_id = $user_id");
        } else {
            db_query("UPDATE cart SET quantity = $qty WHERE id = $cart_id AND user_id = $user_id");
        }
    }
    $_SESSION['flash_msg']  = 'Cart updated!';
    $_SESSION['flash_type'] = 'success';
    header('Location: /vuln-shop/cart.php');
    exit;
}

// Fetch cart items
$cart_items = db_fetch_all("SELECT c.id as cart_id, c.quantity, p.id as product_id,
                                   p.name, p.price, p.image, p.stock
                            FROM cart c
                            JOIN products p ON c.product_id = p.id
                            WHERE c.user_id = $user_id");

$subtotal = 0;
foreach ($cart_items as $item) {
    $subtotal += $item['price'] * $item['quantity'];
}
$shipping = $subtotal > 50 ? 0 : 9.99;
$total    = $subtotal + $shipping;
?>

<div class="page-title">
    <h1><i class="fas fa-shopping-cart"></i> Your Cart</h1>
</div>

<?php if (empty($cart_items)): ?>
<div class="empty-state">
    <i class="fas fa-shopping-cart" style="font-size:4rem;color:#ccc;display:block;text-align:center;margin:20px"></i>
    <p style="text-align:center">Your cart is empty.</p>
    <div style="text-align:center">
        <a href="/vuln-shop/index.php" class="btn btn-primary">Continue Shopping</a>
    </div>
</div>
<?php else: ?>

<!-- VULNERABILITY: no CSRF token on update form -->
<form method="POST" class="cart-form">
<div class="cart-layout">
    <!-- Cart Items -->
    <div class="cart-items">
        <table class="cart-table">
            <thead>
                <tr>
                    <th colspan="2">Product</th>
                    <th>Price</th>
                    <th>Quantity</th>
                    <th>Total</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($cart_items as $item): ?>
            <tr>
                <td class="cart-img-cell">
                    <img src="/vuln-shop/images/<?php echo $item['image']; ?>"
                         onerror="this.src='/vuln-shop/images/placeholder.png'"
                         alt="" style="width:60px;height:60px;object-fit:cover;border-radius:6px">
                </td>
                <td>
                    <!-- VULNERABILITY: product name raw -->
                    <a href="/vuln-shop/product.php?id=<?php echo $item['product_id']; ?>">
                        <?php echo $item['name']; ?>
                    </a>
                </td>
                <td>$<?php echo number_format($item['price'], 2); ?></td>
                <td>
                    <!-- VULNERABILITY: quantity input allows negative values -->
                    <input type="number" name="quantities[<?php echo $item['cart_id']; ?>]"
                           value="<?php echo $item['quantity']; ?>"
                           min="-999" max="999"
                           class="qty-input">
                </td>
                <td>$<?php echo number_format($item['price'] * $item['quantity'], 2); ?></td>
                <td>
                    <!-- VULNERABILITY: IDOR - cart_id not validated against user -->
                    <a href="/vuln-shop/cart.php?action=remove&cart_id=<?php echo $item['cart_id']; ?>"
                       class="btn btn-sm btn-danger">
                        <i class="fas fa-trash"></i>
                    </a>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>

        <div class="cart-actions">
            <a href="/vuln-shop/index.php" class="btn btn-outline">
                <i class="fas fa-arrow-left"></i> Continue Shopping
            </a>
            <button type="submit" name="update_cart" class="btn btn-secondary">
                <i class="fas fa-sync"></i> Update Cart
            </button>
        </div>
    </div>

    <!-- Order Summary -->
    <div class="cart-summary">
        <h3>Order Summary</h3>
        <div class="summary-row">
            <span>Subtotal</span>
            <span>$<?php echo number_format($subtotal, 2); ?></span>
        </div>
        <div class="summary-row">
            <span>Shipping</span>
            <span><?php echo $shipping > 0 ? '$' . number_format($shipping, 2) : '<span style="color:green">FREE</span>'; ?></span>
        </div>
        <div class="summary-row summary-total">
            <span>Total</span>
            <span>$<?php echo number_format($total, 2); ?></span>
        </div>
        <a href="/vuln-shop/checkout.php" class="btn btn-primary btn-block btn-lg">
            <i class="fas fa-credit-card"></i> Proceed to Checkout
        </a>

        <!-- Lab hint -->
        <div class="lab-hint" style="margin-top:15px">
            <h4><i class="fas fa-flask"></i> CSRF PoC</h4>
            <p>This form has no CSRF token. Host this on an attacker page:</p>
            <code style="font-size:0.75rem">
                &lt;img src="http://vulnshop/cart.php?action=add&product_id=1&qty=99"&gt;
            </code>
        </div>
    </div>
</div>
</form>
<?php endif; ?>

<?php require_once 'includes/footer.php'; ?>
