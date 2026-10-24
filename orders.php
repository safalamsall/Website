<?php
// ============================================================
//  VulnShop - Order History / Order Detail
//  VULNERABILITIES:
//  - IDOR: any logged-in user can view any order by changing 'id'
//  - SQLi: order id injected raw
//  - XSS: shipping address echoed raw (stored XSS)
// ============================================================
$page_title = 'My Orders';
require_once 'includes/header.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: /vuln-shop/login.php');
    exit;
}

$user_id = $_SESSION['user_id'];

// View specific order - VULNERABILITY: no ownership check (IDOR)
if (isset($_GET['id'])) {
    $order_id = $_GET['id']; // raw
    // VULNERABILITY: $order_id raw in SQL; no WHERE user_id check
    $order = db_fetch_one("SELECT o.*, u.username, u.email
                           FROM orders o
                           JOIN users u ON o.user_id = u.id
                           WHERE o.id = $order_id");

    if (!$order) {
        echo '<div class="alert alert-danger">Order not found.</div>';
        require_once 'includes/footer.php';
        exit;
    }

    $items = db_fetch_all("SELECT oi.*, p.name, p.image
                           FROM order_items oi
                           JOIN products p ON oi.product_id = p.id
                           WHERE oi.order_id = $order_id");
    ?>
    <div class="page-title">
        <h1>Order #<?php echo $order['id']; ?></h1>
        <a href="/vuln-shop/orders.php" class="btn btn-outline">← All Orders</a>
    </div>

    <div class="order-detail-wrap">
        <div class="order-info-grid">
            <div class="order-info-card">
                <h4>Order Info</h4>
                <p><strong>Status:</strong> <span class="status-badge status-<?php echo $order['status']; ?>"><?php echo $order['status']; ?></span></p>
                <p><strong>Date:</strong> <?php echo $order['created_at']; ?></p>
                <p><strong>Total:</strong> $<?php echo number_format($order['total'], 2); ?></p>
            </div>
            <div class="order-info-card">
                <h4>Customer</h4>
                <p><strong>Username:</strong> <?php echo $order['username']; ?></p>
                <p><strong>Email:</strong> <?php echo $order['email']; ?></p>
            </div>
            <div class="order-info-card">
                <h4>Shipping Address</h4>
                <!-- VULNERABILITY: shipping_address echoed raw — stored XSS -->
                <p><?php echo $order['shipping_address']; ?></p>
            </div>
        </div>

        <div class="lab-hint" style="margin-bottom:20px">
            <h4><i class="fas fa-flask"></i> IDOR Test</h4>
            <p>Change the <code>id</code> parameter in the URL to view other users' orders.
            No ownership check is performed.</p>
            <p>Try: <a href="/vuln-shop/orders.php?id=1">/orders.php?id=1</a>,
                    <a href="/vuln-shop/orders.php?id=2">/orders.php?id=2</a>, etc.</p>
        </div>

        <h3>Items</h3>
        <table class="cart-table">
            <thead>
                <tr><th>Product</th><th>Qty</th><th>Unit Price</th><th>Total</th></tr>
            </thead>
            <tbody>
            <?php foreach ($items as $item): ?>
            <tr>
                <td>
                    <img src="/vuln-shop/images/<?php echo $item['image']; ?>"
                         onerror="this.src='/vuln-shop/images/placeholder.png'"
                         style="width:40px;height:40px;object-fit:cover;border-radius:4px;margin-right:8px;vertical-align:middle">
                    <!-- VULNERABILITY: name raw -->
                    <?php echo $item['name']; ?>
                </td>
                <td><?php echo $item['quantity']; ?></td>
                <td>$<?php echo number_format($item['price'], 2); ?></td>
                <td>$<?php echo number_format($item['price'] * $item['quantity'], 2); ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

<?php } else {
    // List all orders for current user (no IDOR here — filtered by session user_id)
    $orders = db_fetch_all("SELECT * FROM orders WHERE user_id = $user_id ORDER BY created_at DESC");
    ?>
    <div class="page-title">
        <h1><i class="fas fa-box"></i> My Orders</h1>
    </div>

    <?php if (empty($orders)): ?>
        <div class="empty-state">
            <i class="fas fa-box-open" style="font-size:3rem;color:#ccc;display:block;text-align:center;margin:20px"></i>
            <p style="text-align:center">You have no orders yet.</p>
            <div style="text-align:center"><a href="/vuln-shop/index.php" class="btn btn-primary">Start Shopping</a></div>
        </div>
    <?php else: ?>
        <table class="cart-table">
            <thead>
                <tr><th>Order ID</th><th>Date</th><th>Status</th><th>Total</th><th>Action</th></tr>
            </thead>
            <tbody>
            <?php foreach ($orders as $order): ?>
            <tr>
                <td>#<?php echo $order['id']; ?></td>
                <td><?php echo $order['created_at']; ?></td>
                <td><span class="status-badge status-<?php echo $order['status']; ?>"><?php echo $order['status']; ?></span></td>
                <td>$<?php echo number_format($order['total'], 2); ?></td>
                <td>
                    <a href="/vuln-shop/orders.php?id=<?php echo $order['id']; ?>" class="btn btn-sm btn-primary">View</a>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>

        <div class="lab-hint" style="margin-top:20px">
            <h4><i class="fas fa-flask"></i> IDOR Test</h4>
            <p>View order detail then modify the <code>id</code> param to access other users' orders.</p>
        </div>
    <?php endif; ?>
<?php } ?>

<?php require_once 'includes/footer.php'; ?>
