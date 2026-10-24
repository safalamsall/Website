<?php
// ============================================================
//  VulnShop - Invoice / File Download
//  VULNERABILITIES:
//  - Insecure Direct Object Reference (IDOR): order ID not verified against user
//  - Path Traversal via 'file' param in download mode
//  - Sensitive file download: invoices contain PII
//  - No authentication check on file param mode
//  - Arbitrary file read via file param + path traversal
// ============================================================
require_once 'includes/db.php';
session_start();

$type = isset($_GET['type']) ? $_GET['type'] : 'invoice';

if ($type === 'invoice') {
    // VULNERABILITY: order_id not checked against session user (IDOR)
    $order_id = isset($_GET['order_id']) ? $_GET['order_id'] : '';

    if ($order_id === '') {
        header('Location: /vuln-shop/orders.php');
        exit;
    }

    // VULNERABILITY: $order_id raw in SQL, no ownership check
    $order = db_fetch_one("SELECT o.*, u.username, u.email, u.full_name, u.phone, u.address
                           FROM orders o
                           JOIN users u ON o.user_id = u.id
                           WHERE o.id = $order_id");

    if (!$order) {
        die('<h3>Order not found.</h3>');
    }

    $items = db_fetch_all("SELECT oi.*, p.name FROM order_items oi
                           JOIN products p ON oi.product_id = p.id
                           WHERE oi.order_id = $order_id");

    // Serve as plain-text "invoice" (exposes all PII)
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="invoice-' . $order_id . '.txt"');

    echo "===================================================\n";
    echo "  VULNSHOP INVOICE\n";
    echo "===================================================\n";
    echo "Order ID:    #" . $order['id']         . "\n";
    echo "Date:        "  . $order['created_at'] . "\n";
    echo "Status:      "  . $order['status']     . "\n";
    echo "---------------------------------------------------\n";
    echo "Customer:    "  . $order['full_name']  . "\n";
    echo "Username:    "  . $order['username']   . "\n";
    echo "Email:       "  . $order['email']      . "\n";
    echo "Phone:       "  . $order['phone']      . "\n";
    echo "Address:     "  . $order['address']    . "\n";
    echo "Shipping:    "  . $order['shipping_address'] . "\n";
    echo "---------------------------------------------------\n";
    echo "ITEMS:\n";
    foreach ($items as $item) {
        echo sprintf("  %-30s x%d  \$%.2f\n", $item['name'], $item['quantity'], $item['price']);
    }
    echo "---------------------------------------------------\n";
    echo sprintf("  TOTAL: \$%.2f\n", $order['total']);
    echo "===================================================\n";
    echo "  Thank you for shopping at VulnShop!\n";
    echo "===================================================\n";
    exit;
}

if ($type === 'file') {
    // VULNERABILITY: 'file' param passed raw — path traversal + arbitrary file download
    // No authentication required at all
    $file = isset($_GET['file']) ? $_GET['file'] : '';

    if ($file === '') {
        die('No file specified. Use ?type=file&file=PATH');
    }

    // VULNERABILITY: no path restriction, serves any readable file
    $content = @file_get_contents($file);

    if ($content === false) {
        // Try relative to document root
        $content = @file_get_contents($_SERVER['DOCUMENT_ROOT'] . '/' . $file);
    }

    if ($content === false) {
        http_response_code(404);
        die('File not found or not readable: ' . htmlspecialchars($file));
    }

    // VULNERABILITY: original filename used in Content-Disposition
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($file) . '"');
    header('Content-Length: ' . strlen($content));
    echo $content;
    exit;
}

// ---- HTML page version (shown when no download params given) ----
$page_title = 'Downloads';
require_once 'includes/header.php';

$user_id = $_SESSION['user_id'] ?? 0;
// Fetch orders (but page also shows how to download ANY order by ID)
$orders = $user_id ? db_fetch_all("SELECT * FROM orders WHERE user_id = $user_id ORDER BY created_at DESC LIMIT 10") : [];
?>

<div class="page-title">
    <h1><i class="fas fa-download"></i> Downloads &amp; Invoices</h1>
    <span class="vuln-tag">IDOR / Path Traversal</span>
</div>

<div class="lab-hint">
    <h4><i class="fas fa-flask"></i> Vulnerabilities: IDOR + Path Traversal Download</h4>
    <table>
        <tr><th>Attack</th><th>URL</th></tr>
        <tr><td>Download any order invoice (IDOR)</td>  <td><code>/download.php?type=invoice&order_id=1</code></td></tr>
        <tr><td>Download DB config</td>                 <td><code>/download.php?type=file&file=includes/db.php</code></td></tr>
        <tr><td>Download /etc/passwd</td>               <td><code>/download.php?type=file&file=../../../../../../../etc/passwd</code></td></tr>
        <tr><td>Download win.ini</td>                   <td><code>/download.php?type=file&file=../../../../../../../windows/win.ini</code></td></tr>
        <tr><td>Download .htaccess</td>                 <td><code>/download.php?type=file&file=.htaccess</code></td></tr>
        <tr><td>Download SQL schema</td>                <td><code>/download.php?type=file&file=database.sql</code></td></tr>
    </table>
</div>

<div class="two-col-layout">
    <div class="checkout-section">
        <h3><i class="fas fa-file-invoice"></i> My Invoices (IDOR)</h3>
        <?php if (empty($orders)): ?>
            <p style="color:#94a3b8">No orders yet. <a href="/vuln-shop/index.php">Shop now</a>.</p>
        <?php else: ?>
            <table class="cart-table">
                <thead><tr><th>Order</th><th>Date</th><th>Total</th><th>Download</th></tr></thead>
                <tbody>
                <?php foreach ($orders as $o): ?>
                <tr>
                    <td>#<?php echo $o['id']; ?></td>
                    <td><?php echo $o['created_at']; ?></td>
                    <td>$<?php echo number_format($o['total'], 2); ?></td>
                    <td>
                        <a href="download.php?type=invoice&order_id=<?php echo $o['id']; ?>"
                           class="btn btn-sm btn-primary">
                            <i class="fas fa-download"></i> Invoice
                        </a>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
        <div class="lab-hint" style="margin-top:12px">
            <p>Try any order ID: <a href="download.php?type=invoice&order_id=1">#1</a>,
               <a href="download.php?type=invoice&order_id=2">#2</a>,
               <a href="download.php?type=invoice&order_id=3">#3</a>
               &mdash; no ownership check!</p>
        </div>
    </div>

    <div class="checkout-section">
        <h3><i class="fas fa-folder-open"></i> Arbitrary File Download</h3>
        <form method="GET">
            <input type="hidden" name="type" value="file">
            <div class="form-group">
                <label>File Path <small style="color:#e74c3c">(path traversal — no restriction)</small></label>
                <input type="text" name="file" class="form-control"
                       placeholder="../../../etc/passwd">
            </div>
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-download"></i> Download
            </button>
        </form>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px">
            <a href="download.php?type=file&file=includes/db.php"         class="btn btn-sm btn-danger">db.php</a>
            <a href="download.php?type=file&file=database.sql"            class="btn btn-sm btn-danger">database.sql</a>
            <a href="download.php?type=file&file=.htaccess"               class="btn btn-sm btn-outline">.htaccess</a>
            <a href="download.php?type=file&file=../../../etc/passwd"     class="btn btn-sm btn-danger">/etc/passwd</a>
            <a href="download.php?type=file&file=../../../windows/win.ini" class="btn btn-sm btn-warning">win.ini</a>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>
