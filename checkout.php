<?php
// ============================================================
//  VulnShop - Checkout Page
//  VULNERABILITIES:
//  - SQLi: coupon code injected raw into SELECT query
//  - CSRF: no token on checkout form
//  - XSS: shipping address stored and echoed raw
//  - Insecure direct price: total calculated client-side and trusted
//  - Coupon abuse: 'HACK50' gives 50% off; no single-use enforcement
// ============================================================
$page_title = 'Checkout';
require_once 'includes/header.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: /vuln-shop/login.php');
    exit;
}

$user_id  = $_SESSION['user_id'];
$user     = db_fetch_one("SELECT * FROM users WHERE id = $user_id");
$cart_items = db_fetch_all("SELECT c.id as cart_id, c.quantity, p.id as product_id,
                                   p.name, p.price, p.image
                            FROM cart c
                            JOIN products p ON c.product_id = p.id
                            WHERE c.user_id = $user_id");

if (empty($cart_items)) {
    header('Location: /vuln-shop/cart.php');
    exit;
}

$subtotal = 0;
foreach ($cart_items as $item) {
    $subtotal += $item['price'] * $item['quantity'];
}

$discount    = 0;
$coupon_msg  = '';
$coupon_code = '';

// Handle coupon check
if (isset($_POST['apply_coupon'])) {
    $coupon_code = $_POST['coupon_code'];
    // VULNERABILITY: coupon_code injected raw — SQLi
    // Payload: ' OR active=1 AND discount > 0 -- 
    $coupon = db_fetch_one("SELECT * FROM coupons WHERE code = '$coupon_code' AND active = 1");
    if ($coupon) {
        $discount   = $coupon['discount'];
        $coupon_msg = "<span style='color:green'>Coupon applied! {$discount}% off.</span>";
        $_SESSION['discount']     = $discount;
        $_SESSION['coupon_code']  = $coupon_code;
    } else {
        $coupon_msg = "<span style='color:red'>Invalid or expired coupon code.</span>";
        $discount   = 0;
    }
}

// Restore discount from session
if (isset($_SESSION['discount'])) {
    $discount    = $_SESSION['discount'];
    $coupon_code = $_SESSION['coupon_code'] ?? '';
}

$discount_amount = $subtotal * ($discount / 100);
$shipping        = ($subtotal - $discount_amount) > 50 ? 0 : 9.99;
$total           = $subtotal - $discount_amount + $shipping;

// Handle order submission
$order_error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['place_order'])) {
    $shipping_addr = $_POST['shipping_address'];
    $card_num      = $_POST['card_number']  ?? '';  // VULNERABILITY: credit card stored in plain text
    $card_exp      = $_POST['card_expiry']  ?? '';
    $card_cvv      = $_POST['card_cvv']     ?? '';

    if (empty($shipping_addr)) {
        $order_error = 'Shipping address is required.';
    } else {
        // VULNERABILITY: shipping address raw in SQL (stored XSS in admin view)
        $order_id = db_insert("INSERT INTO orders (user_id, total, status, shipping_address)
                               VALUES ($user_id, $total, 'pending', '$shipping_addr')");

        if ($order_id) {
            foreach ($cart_items as $item) {
                db_query("INSERT INTO order_items (order_id, product_id, quantity, price)
                          VALUES ($order_id, {$item['product_id']}, {$item['quantity']}, {$item['price']})");
                db_query("UPDATE products SET stock = stock - {$item['quantity']}
                          WHERE id = {$item['product_id']}");
            }

            // Clear cart and discount
            db_query("DELETE FROM cart WHERE user_id = $user_id");
            unset($_SESSION['discount'], $_SESSION['coupon_code']);

            $_SESSION['flash_msg']  = "Order #$order_id placed successfully! Thank you!";
            $_SESSION['flash_type'] = 'success';
            header("Location: /vuln-shop/orders.php?id=$order_id");
            exit;
        }
    }
}
?>

<div class="page-title">
    <h1><i class="fas fa-credit-card"></i> Checkout</h1>
</div>

<?php if ($order_error): ?>
    <div class="alert alert-danger"><?php echo $order_error; ?></div>
<?php endif; ?>

<!-- VULNERABILITY: no CSRF token -->
<form method="POST" class="checkout-form">
<div class="checkout-layout">

    <!-- Left: Shipping & Payment -->
    <div class="checkout-left">

        <!-- Shipping -->
        <div class="checkout-section">
            <h3><i class="fas fa-truck"></i> Shipping Information</h3>
            <div class="form-group">
                <label>Full Name</label>
                <!-- VULNERABILITY: user data echoed raw -->
                <input type="text" class="form-control" name="full_name"
                       value="<?php echo $user['full_name']; ?>">
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="text" class="form-control" name="email"
                       value="<?php echo $user['email']; ?>">
            </div>
            <div class="form-group">
                <label>Shipping Address *</label>
                <!-- VULNERABILITY: stored raw in orders table -->
                <textarea name="shipping_address" class="form-control" rows="3"
                          placeholder="123 Main St, City, State, ZIP"><?php echo $user['address']; ?></textarea>
            </div>
            <div class="form-group">
                <label>Phone</label>
                <input type="text" class="form-control" name="phone"
                       value="<?php echo $user['phone']; ?>">
            </div>
        </div>

        <!-- Payment (fake, but stores card data in plain text) -->
        <div class="checkout-section">
            <h3><i class="fas fa-credit-card"></i> Payment Details
                <span style="color:#e74c3c;font-size:0.75rem"> (stored in plain text — insecure!)</span>
            </h3>
            <div class="form-group">
                <label>Card Number</label>
                <input type="text" class="form-control" name="card_number"
                       placeholder="4111 1111 1111 1111" maxlength="19">
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Expiry</label>
                    <input type="text" class="form-control" name="card_expiry"
                           placeholder="MM/YY" maxlength="5">
                </div>
                <div class="form-group">
                    <label>CVV</label>
                    <input type="text" class="form-control" name="card_cvv"
                           placeholder="123" maxlength="4">
                </div>
            </div>
        </div>

        <!-- Coupon -->
        <div class="checkout-section">
            <h3><i class="fas fa-tag"></i> Coupon Code</h3>
            <!-- VULNERABILITY: coupon SQLi via raw input -->
            <div class="coupon-row">
                <input type="text" name="coupon_code" class="form-control"
                       value="<?php echo $coupon_code; ?>"
                       placeholder="Enter coupon code">
                <button type="submit" name="apply_coupon" class="btn btn-secondary">Apply</button>
            </div>
            <?php if ($coupon_msg): ?>
                <!-- VULNERABILITY: coupon_msg echoed raw -->
                <p style="margin-top:8px"><?php echo $coupon_msg; ?></p>
            <?php endif; ?>
            <div class="lab-hint" style="margin-top:10px">
                <h4><i class="fas fa-flask"></i> Coupon SQLi</h4>
                <p>Payload: <code>' OR active=1 LIMIT 1--</code></p>
                <p>Valid codes: SAVE10, WELCOME20, HACK50</p>
            </div>
        </div>
    </div>

    <!-- Right: Order Summary -->
    <div class="checkout-right">
        <div class="checkout-section">
            <h3><i class="fas fa-list"></i> Order Summary</h3>

            <?php foreach ($cart_items as $item): ?>
            <div class="order-item-row">
                <img src="/vuln-shop/images/<?php echo $item['image']; ?>"
                     onerror="this.src='/vuln-shop/images/placeholder.png'"
                     style="width:40px;height:40px;object-fit:cover;border-radius:4px">
                <div class="order-item-name">
                    <!-- VULNERABILITY: product name raw -->
                    <?php echo $item['name']; ?>
                    <small>x<?php echo $item['quantity']; ?></small>
                </div>
                <div>$<?php echo number_format($item['price'] * $item['quantity'], 2); ?></div>
            </div>
            <?php endforeach; ?>

            <div class="summary-divider"></div>

            <div class="summary-row">
                <span>Subtotal</span>
                <span>$<?php echo number_format($subtotal, 2); ?></span>
            </div>
            <?php if ($discount > 0): ?>
            <div class="summary-row" style="color:green">
                <span>Discount (<?php echo $discount; ?>%)</span>
                <span>-$<?php echo number_format($discount_amount, 2); ?></span>
            </div>
            <?php endif; ?>
            <div class="summary-row">
                <span>Shipping</span>
                <span><?php echo $shipping > 0 ? '$'.number_format($shipping,2) : 'FREE'; ?></span>
            </div>
            <div class="summary-row summary-total">
                <span>Total</span>
                <span>$<?php echo number_format($total, 2); ?></span>
            </div>

            <button type="submit" name="place_order" class="btn btn-primary btn-block btn-lg" style="margin-top:15px">
                <i class="fas fa-check-circle"></i> Place Order
            </button>
            <a href="/vuln-shop/cart.php" class="btn btn-outline btn-block" style="margin-top:8px">
                <i class="fas fa-arrow-left"></i> Back to Cart
            </a>
        </div>
    </div>

</div>
</form>

<?php require_once 'includes/footer.php'; ?>
