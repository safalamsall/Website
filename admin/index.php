<?php
// ============================================================
//  VulnShop - Admin Panel
//  VULNERABILITIES:
//  - Broken Access Control: only checks role from SESSION
//    but session role can be set via mass assignment on register
//  - SQLi: search/filter params raw in SQL
//  - XSS: user-supplied data echoed raw throughout
//  - Sensitive data exposure: shows all plain-text passwords
//  - No CSRF tokens
// ============================================================
$page_title = 'Admin Panel';
require_once '../includes/header.php';

// VULNERABILITY: only client-side session check — bypass via mass assignment
// Register with role=admin or SQLi login bypass to get admin session
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    // VULNERABILITY: leaks that the admin panel exists at this path
    echo '<div class="alert alert-danger" style="margin:40px auto;max-width:500px;text-align:center">
            <h3>Access Denied</h3>
            <p>Admin access required. But you can bypass this by:<br>
            1. Logging in as admin/admin123<br>
            2. SQLi login bypass: username <code>admin\'--</code><br>
            3. Register with <code>role=admin</code> in POST body</p>
            <a href="/vuln-shop/login.php" class="btn btn-primary">Login</a>
          </div>';
    require_once '../includes/footer.php';
    exit;
}

$section = isset($_GET['section']) ? $_GET['section'] : 'dashboard';
?>

<div class="admin-layout">
    <!-- Admin Sidebar -->
    <aside class="admin-sidebar">
        <h3><i class="fas fa-cog"></i> Admin Panel</h3>
        <nav class="admin-nav">
            <a href="?section=dashboard"  class="<?php echo $section=='dashboard'?'active':''; ?>"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
            <a href="?section=users"      class="<?php echo $section=='users'?'active':''; ?>"><i class="fas fa-users"></i> Users</a>
            <a href="?section=products"   class="<?php echo $section=='products'?'active':''; ?>"><i class="fas fa-box"></i> Products</a>
            <a href="?section=orders"     class="<?php echo $section=='orders'?'active':''; ?>"><i class="fas fa-shopping-bag"></i> Orders</a>
            <a href="?section=messages"   class="<?php echo $section=='messages'?'active':''; ?>"><i class="fas fa-envelope"></i> Messages</a>
            <a href="?section=coupons"    class="<?php echo $section=='coupons'?'active':''; ?>"><i class="fas fa-tag"></i> Coupons</a>
        </nav>
    </aside>

    <!-- Admin Content -->
    <div class="admin-content">

    <?php if ($section === 'dashboard'): ?>
        <h2>Dashboard</h2>
        <?php
        $user_count    = db_fetch_one("SELECT COUNT(*) as c FROM users")['c'];
        $product_count = db_fetch_one("SELECT COUNT(*) as c FROM products")['c'];
        $order_count   = db_fetch_one("SELECT COUNT(*) as c FROM orders")['c'];
        $revenue       = db_fetch_one("SELECT SUM(total) as t FROM orders")['t'];
        $review_count  = db_fetch_one("SELECT COUNT(*) as c FROM reviews")['c'];
        $msg_count     = db_fetch_one("SELECT COUNT(*) as c FROM messages")['c'];
        ?>
        <div class="dash-stats">
            <div class="stat-card"><i class="fas fa-users"></i><div><span><?php echo $user_count; ?></span><p>Users</p></div></div>
            <div class="stat-card"><i class="fas fa-box"></i><div><span><?php echo $product_count; ?></span><p>Products</p></div></div>
            <div class="stat-card"><i class="fas fa-shopping-bag"></i><div><span><?php echo $order_count; ?></span><p>Orders</p></div></div>
            <div class="stat-card"><i class="fas fa-dollar-sign"></i><div><span>$<?php echo number_format($revenue ?? 0, 2); ?></span><p>Revenue</p></div></div>
            <div class="stat-card"><i class="fas fa-star"></i><div><span><?php echo $review_count; ?></span><p>Reviews</p></div></div>
            <div class="stat-card"><i class="fas fa-envelope"></i><div><span><?php echo $msg_count; ?></span><p>Messages</p></div></div>
        </div>

        <div class="lab-hint" style="margin-top:20px">
            <h4><i class="fas fa-flask"></i> Admin Panel Vulnerabilities</h4>
            <ul>
                <li><strong>Broken Access Control:</strong> Register a new account with <code>role=admin</code> via Burp Suite, then access this page</li>
                <li><strong>SQLi Login Bypass:</strong> Use <code>admin'--</code> as username</li>
                <li><strong>Sensitive Exposure:</strong> Check Users tab — all passwords shown in plain text</li>
                <li><strong>Stored XSS:</strong> Check Messages tab — user input rendered raw</li>
            </ul>
        </div>

    <?php elseif ($section === 'users'): ?>
        <h2>Users
            <small style="color:#e74c3c;font-size:0.8rem">— Passwords shown in plain text (vulnerability)</small>
        </h2>
        <?php
        // VULNERABILITY: search param raw in SQL
        $search = isset($_GET['search']) ? $_GET['search'] : '';
        if ($search) {
            $users = db_fetch_all("SELECT * FROM users WHERE username LIKE '%$search%' OR email LIKE '%$search%'");
        } else {
            $users = db_fetch_all("SELECT * FROM users ORDER BY id");
        }

        // Handle delete
        if (isset($_GET['delete_user'])) {
            $del_id = $_GET['delete_user']; // raw
            db_query("DELETE FROM users WHERE id = $del_id");
            echo '<div class="alert alert-success">User deleted.</div>';
            $users = db_fetch_all("SELECT * FROM users ORDER BY id");
        }

        // Handle role change
        if (isset($_POST['change_role'])) {
            $uid  = $_POST['uid'];
            $role = $_POST['new_role'];
            db_query("UPDATE users SET role='$role' WHERE id=$uid");
            echo '<div class="alert alert-success">Role updated.</div>';
            $users = db_fetch_all("SELECT * FROM users ORDER BY id");
        }
        ?>

        <!-- VULNERABILITY: search reflected raw -->
        <form method="GET" style="margin-bottom:15px;display:flex;gap:8px">
            <input type="hidden" name="section" value="users">
            <input type="text" name="search" class="form-control" style="width:250px"
                   value="<?php echo $search; ?>" placeholder="Search users...">
            <button class="btn btn-secondary">Search</button>
        </form>

        <div style="overflow-x:auto">
        <table class="admin-table">
            <thead>
                <tr>
                    <th>ID</th><th>Username</th><th>Email</th>
                    <th style="color:#e74c3c">Password (PLAIN TEXT)</th>
                    <th>Role</th><th>Joined</th><th>Actions</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($users as $u): ?>
            <tr>
                <td><?php echo $u['id']; ?></td>
                <!-- VULNERABILITY: all fields echoed raw — stored XSS -->
                <td><?php echo $u['username']; ?></td>
                <td><?php echo $u['email']; ?></td>
                <td style="color:#e74c3c;font-family:monospace"><?php echo $u['password']; ?></td>
                <td>
                    <form method="POST" style="display:inline">
                        <input type="hidden" name="uid" value="<?php echo $u['id']; ?>">
                        <select name="new_role" class="form-control" style="width:auto;display:inline">
                            <option <?php echo $u['role']=='user'?'selected':''; ?>>user</option>
                            <option <?php echo $u['role']=='admin'?'selected':''; ?>>admin</option>
                        </select>
                        <button type="submit" name="change_role" class="btn btn-sm btn-secondary">Set</button>
                    </form>
                </td>
                <td><?php echo $u['created_at']; ?></td>
                <td>
                    <a href="?section=users&delete_user=<?php echo $u['id']; ?>"
                       onclick="return confirm('Delete user <?php echo $u['username']; ?>?')"
                       class="btn btn-sm btn-danger">Delete</a>
                    <a href="/vuln-shop/profile.php?id=<?php echo $u['id']; ?>" class="btn btn-sm btn-primary">Profile</a>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>

    <?php elseif ($section === 'products'): ?>
        <h2>Products</h2>

        <!-- Add Product Form -->
        <?php
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_product'])) {
            $pname = $_POST['pname'];
            $pdesc = $_POST['pdesc'];
            $price = $_POST['price'];
            $stock = $_POST['stock'];
            $catid = $_POST['category_id'];
            // VULNERABILITY: all fields raw in INSERT
            db_insert("INSERT INTO products (name, description, price, stock, category_id)
                       VALUES ('$pname', '$pdesc', $price, $stock, $catid)");
            echo '<div class="alert alert-success">Product added!</div>';
        }

        if (isset($_GET['delete_product'])) {
            $pid = $_GET['delete_product'];
            db_query("DELETE FROM products WHERE id = $pid");
            echo '<div class="alert alert-success">Product deleted.</div>';
        }

        $products = db_fetch_all("SELECT p.*, c.name as cat_name FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.id DESC");
        $cats     = db_fetch_all("SELECT * FROM categories");
        ?>

        <form method="POST" class="admin-add-form">
            <h4>Add New Product</h4>
            <div class="form-row">
                <div class="form-group"><label>Name</label><input type="text" name="pname" class="form-control" placeholder="Product name"></div>
                <div class="form-group"><label>Price</label><input type="text" name="price" class="form-control" placeholder="9.99"></div>
            </div>
            <div class="form-group"><label>Description</label><textarea name="pdesc" class="form-control" rows="2"></textarea></div>
            <div class="form-row">
                <div class="form-group"><label>Stock</label><input type="text" name="stock" class="form-control" placeholder="100"></div>
                <div class="form-group">
                    <label>Category</label>
                    <select name="category_id" class="form-control">
                        <?php foreach ($cats as $c): ?><option value="<?php echo $c['id']; ?>"><?php echo $c['name']; ?></option><?php endforeach; ?>
                    </select>
                </div>
            </div>
            <button type="submit" name="add_product" class="btn btn-primary">Add Product</button>
        </form>

        <div style="overflow-x:auto;margin-top:20px">
        <table class="admin-table">
            <thead><tr><th>ID</th><th>Name</th><th>Price</th><th>Stock</th><th>Category</th><th>Actions</th></tr></thead>
            <tbody>
            <?php foreach ($products as $p): ?>
            <tr>
                <td><?php echo $p['id']; ?></td>
                <td><?php echo $p['name']; ?></td>
                <td>$<?php echo $p['price']; ?></td>
                <td><?php echo $p['stock']; ?></td>
                <td><?php echo $p['cat_name']; ?></td>
                <td>
                    <a href="/vuln-shop/product.php?id=<?php echo $p['id']; ?>" class="btn btn-sm btn-primary">View</a>
                    <a href="?section=products&delete_product=<?php echo $p['id']; ?>"
                       onclick="return confirm('Delete?')" class="btn btn-sm btn-danger">Delete</a>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>

    <?php elseif ($section === 'orders'): ?>
        <h2>All Orders</h2>
        <?php
        if (isset($_POST['update_status'])) {
            $oid    = $_POST['order_id'];
            $status = $_POST['status'];
            db_query("UPDATE orders SET status='$status' WHERE id=$oid");
            echo '<div class="alert alert-success">Status updated.</div>';
        }
        $orders = db_fetch_all("SELECT o.*, u.username FROM orders o LEFT JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC");
        ?>
        <div style="overflow-x:auto">
        <table class="admin-table">
            <thead><tr><th>ID</th><th>Customer</th><th>Total</th><th>Status</th><th>Date</th><th>Actions</th></tr></thead>
            <tbody>
            <?php foreach ($orders as $o): ?>
            <tr>
                <td>#<?php echo $o['id']; ?></td>
                <!-- VULNERABILITY: username raw — stored XSS -->
                <td><?php echo $o['username']; ?></td>
                <td>$<?php echo number_format($o['total'], 2); ?></td>
                <td>
                    <form method="POST" style="display:inline">
                        <input type="hidden" name="order_id" value="<?php echo $o['id']; ?>">
                        <select name="status" class="form-control" style="width:auto;display:inline">
                            <?php foreach(['pending','processing','shipped','delivered','cancelled'] as $s): ?>
                            <option <?php echo $o['status']==$s?'selected':''; ?>><?php echo $s; ?></option>
                            <?php endforeach; ?>
                        </select>
                        <button type="submit" name="update_status" class="btn btn-sm btn-secondary">Update</button>
                    </form>
                </td>
                <td><?php echo $o['created_at']; ?></td>
                <td><a href="/vuln-shop/orders.php?id=<?php echo $o['id']; ?>" class="btn btn-sm btn-primary">View</a></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>

    <?php elseif ($section === 'messages'): ?>
        <h2>Contact Messages</h2>
        <?php $messages = db_fetch_all("SELECT * FROM messages ORDER BY created_at DESC"); ?>
        <?php if (empty($messages)): ?>
            <p>No messages yet. Submit one via the <a href="/vuln-shop/contact.php">contact page</a>.</p>
        <?php else: ?>
        <table class="admin-table">
            <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Subject</th><th>Message</th><th>Date</th></tr></thead>
            <tbody>
            <?php foreach ($messages as $m): ?>
            <tr>
                <!-- VULNERABILITY: all fields echoed raw — stored XSS -->
                <td><?php echo $m['id']; ?></td>
                <td><?php echo $m['name']; ?></td>
                <td><?php echo $m['email']; ?></td>
                <td><?php echo $m['subject']; ?></td>
                <td><?php echo $m['message']; ?></td>
                <td><?php echo $m['created_at']; ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>

    <?php elseif ($section === 'coupons'): ?>
        <h2>Coupons</h2>
        <?php
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_coupon'])) {
            $code     = $_POST['code'];
            $discount = $_POST['discount'];
            db_insert("INSERT INTO coupons (code, discount, active) VALUES ('$code', $discount, 1)");
            echo '<div class="alert alert-success">Coupon added!</div>';
        }
        if (isset($_GET['toggle_coupon'])) {
            $cid = $_GET['toggle_coupon'];
            db_query("UPDATE coupons SET active = 1 - active WHERE id = $cid");
        }
        $coupons = db_fetch_all("SELECT * FROM coupons");
        ?>
        <form method="POST" class="admin-add-form">
            <h4>Add Coupon</h4>
            <div class="form-row">
                <div class="form-group"><label>Code</label><input type="text" name="code" class="form-control" placeholder="SAVE10"></div>
                <div class="form-group"><label>Discount %</label><input type="number" name="discount" class="form-control" placeholder="10"></div>
            </div>
            <button type="submit" name="add_coupon" class="btn btn-primary">Add Coupon</button>
        </form>
        <table class="admin-table" style="margin-top:20px">
            <thead><tr><th>ID</th><th>Code</th><th>Discount</th><th>Active</th><th>Action</th></tr></thead>
            <tbody>
            <?php foreach ($coupons as $c): ?>
            <tr>
                <td><?php echo $c['id']; ?></td>
                <td><?php echo $c['code']; ?></td>
                <td><?php echo $c['discount']; ?>%</td>
                <td><?php echo $c['active'] ? '<span style="color:green">Yes</span>' : '<span style="color:red">No</span>'; ?></td>
                <td><a href="?section=coupons&toggle_coupon=<?php echo $c['id']; ?>" class="btn btn-sm btn-secondary">Toggle</a></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>

    <?php endif; ?>

    </div><!-- /.admin-content -->
</div><!-- /.admin-layout -->

<?php require_once '../includes/footer.php'; ?>
