<?php
// ============================================================
//  VulnShop - User Profile
//  VULNERABILITIES:
//  - IDOR: view any user's profile via ?id= param (no auth check)
//  - Stored XSS: bio/username echoed raw on profile view
//  - SQLi: user id raw in SELECT
//  - File upload: no validation of uploaded file type (webshell upload)
//  - CSRF: profile update form has no token
// ============================================================
$page_title = 'Profile';
require_once 'includes/header.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: /vuln-shop/login.php');
    exit;
}

$my_id = $_SESSION['user_id'];

// VULNERABILITY: IDOR - view any user by ?id=X, no ownership check
$view_id = isset($_GET['id']) ? $_GET['id'] : $my_id;
$profile_user = db_fetch_one("SELECT * FROM users WHERE id = $view_id");

if (!$profile_user) {
    echo '<div class="alert alert-danger">User not found.</div>';
    require_once 'includes/footer.php';
    exit;
}

$is_own_profile = ($view_id == $my_id);
$update_msg = '';
$update_err = '';

// Handle profile update (only own profile - but ID comes from POST, not session!)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    // VULNERABILITY: user_id taken from POST not session (IDOR via POST)
    $update_id = isset($_POST['user_id']) ? $_POST['user_id'] : $my_id;
    $full_name  = $_POST['full_name'];
    $email      = $_POST['email'];
    $phone      = $_POST['phone'];
    $address    = $_POST['address'];
    $bio        = $_POST['bio']; // VULNERABILITY: raw — stored XSS

    // Handle avatar upload — VULNERABILITY: no file type validation (webshell upload)
    $avatar = $profile_user['avatar'];
    if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] === UPLOAD_ERR_OK) {
        $tmp  = $_FILES['avatar']['tmp_name'];
        $name = $_FILES['avatar']['name'];
        // VULNERABILITY: original filename used, no extension check
        $dest = __DIR__ . '/uploads/' . $name;
        move_uploaded_file($tmp, $dest);
        $avatar = $name;
    }

    // VULNERABILITY: all fields raw in SQL, update_id from POST
    db_query("UPDATE users SET full_name='$full_name', email='$email',
              phone='$phone', address='$address', bio='$bio', avatar='$avatar'
              WHERE id = $update_id");

    // Refresh session if own profile
    if ($update_id == $my_id) {
        $_SESSION['username'] = $profile_user['username'];
    }

    $update_msg = 'Profile updated successfully!';
    $profile_user = db_fetch_one("SELECT * FROM users WHERE id = $update_id");
}

// Handle password change
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password'])) {
    $old_pass = $_POST['old_password'];
    $new_pass = $_POST['new_password'];
    // VULNERABILITY: plain text comparison, no hashing
    if ($profile_user['password'] === $old_pass) {
        // VULNERABILITY: new password stored as plain text
        db_query("UPDATE users SET password='$new_pass' WHERE id = $view_id");
        $update_msg = 'Password changed successfully!';
    } else {
        $update_err = 'Incorrect current password.';
    }
}
?>

<div class="page-title">
    <h1>
        <i class="fas fa-user-circle"></i>
        <!-- VULNERABILITY: username echoed raw — stored XSS -->
        <?php echo $profile_user['username']; ?>'s Profile
        <?php if (!$is_own_profile): ?>
            <span class="idor-badge">⚠️ Viewing another user's profile (IDOR)</span>
        <?php endif; ?>
    </h1>
</div>

<div class="lab-hint" style="margin-bottom:20px">
    <h4><i class="fas fa-flask"></i> IDOR Test</h4>
    <p>Change the <code>id</code> parameter: <a href="profile.php?id=1">id=1</a>, <a href="profile.php?id=2">id=2</a>, <a href="profile.php?id=3">id=3</a></p>
    <p>Profile update sends <code>user_id</code> in POST body — modify it to update another user's profile.</p>
    <p>Avatar upload accepts any file type — try uploading a PHP webshell: <code>&lt;?php system($_GET['cmd']); ?&gt;</code></p>
</div>

<?php if ($update_msg): ?>
    <div class="alert alert-success"><?php echo $update_msg; ?></div>
<?php endif; ?>
<?php if ($update_err): ?>
    <div class="alert alert-danger"><?php echo $update_err; ?></div>
<?php endif; ?>

<div class="profile-layout">
    <!-- Avatar Card -->
    <div class="profile-sidebar">
        <div class="avatar-card">
            <img src="/vuln-shop/uploads/<?php echo $profile_user['avatar']; ?>"
                 onerror="this.src='/vuln-shop/images/placeholder.png'"
                 alt="Avatar" class="avatar-img">
            <!-- VULNERABILITY: username and bio echoed raw — stored XSS -->
            <h3><?php echo $profile_user['username']; ?></h3>
            <span class="role-badge role-<?php echo $profile_user['role']; ?>"><?php echo $profile_user['role']; ?></span>
            <p class="profile-bio"><?php echo $profile_user['bio']; ?></p>
        </div>

        <div class="profile-meta-card">
            <p><i class="fas fa-envelope"></i> <?php echo $profile_user['email']; ?></p>
            <p><i class="fas fa-phone"></i> <?php echo $profile_user['phone']; ?></p>
            <p><i class="fas fa-map-marker-alt"></i> <?php echo $profile_user['address']; ?></p>
            <p><i class="fas fa-calendar"></i> Joined: <?php echo $profile_user['created_at']; ?></p>
        </div>
    </div>

    <!-- Edit Form -->
    <div class="profile-main">
        <!-- VULNERABILITY: no CSRF token; user_id hidden field is attacker-controlled -->
        <form method="POST" enctype="multipart/form-data" class="profile-form">
            <input type="hidden" name="user_id" value="<?php echo $profile_user['id']; ?>">

            <div class="checkout-section">
                <h3><i class="fas fa-edit"></i> Edit Profile</h3>

                <div class="form-row">
                    <div class="form-group">
                        <label>Username (read-only)</label>
                        <input type="text" class="form-control" value="<?php echo $profile_user['username']; ?>" disabled>
                    </div>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="text" name="email" class="form-control"
                               value="<?php echo $profile_user['email']; ?>">
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label>Full Name</label>
                        <input type="text" name="full_name" class="form-control"
                               value="<?php echo $profile_user['full_name']; ?>">
                    </div>
                    <div class="form-group">
                        <label>Phone</label>
                        <input type="text" name="phone" class="form-control"
                               value="<?php echo $profile_user['phone']; ?>">
                    </div>
                </div>

                <div class="form-group">
                    <label>Address</label>
                    <textarea name="address" class="form-control" rows="2"><?php echo $profile_user['address']; ?></textarea>
                </div>

                <div class="form-group">
                    <label>Bio <small style="color:#e74c3c">(HTML allowed — stored XSS)</small></label>
                    <textarea name="bio" class="form-control" rows="3"><?php echo $profile_user['bio']; ?></textarea>
                </div>

                <div class="form-group">
                    <label>Avatar Upload <small style="color:#e74c3c">(no file type check — try .php webshell)</small></label>
                    <input type="file" name="avatar" class="form-control">
                </div>

                <button type="submit" name="update_profile" class="btn btn-primary">
                    <i class="fas fa-save"></i> Save Changes
                </button>
            </div>
        </form>

        <!-- Password Change -->
        <form method="POST" class="profile-form" style="margin-top:20px">
            <div class="checkout-section">
                <h3><i class="fas fa-key"></i> Change Password</h3>
                <div class="form-group">
                    <label>Current Password</label>
                    <input type="password" name="old_password" class="form-control">
                </div>
                <div class="form-group">
                    <label>New Password</label>
                    <input type="password" name="new_password" class="form-control">
                </div>
                <button type="submit" name="change_password" class="btn btn-secondary">
                    <i class="fas fa-key"></i> Change Password
                </button>
            </div>
        </form>
    </div>
</div>

<!-- User Orders Preview -->
<?php
$user_orders = db_fetch_all("SELECT * FROM orders WHERE user_id = $view_id ORDER BY created_at DESC LIMIT 5");
if (!empty($user_orders)):
?>
<div class="checkout-section" style="margin-top:20px">
    <h3><i class="fas fa-box"></i> Recent Orders</h3>
    <table class="cart-table">
        <thead><tr><th>Order ID</th><th>Date</th><th>Status</th><th>Total</th><th></th></tr></thead>
        <tbody>
        <?php foreach ($user_orders as $o): ?>
        <tr>
            <td>#<?php echo $o['id']; ?></td>
            <td><?php echo $o['created_at']; ?></td>
            <td><span class="status-badge"><?php echo $o['status']; ?></span></td>
            <td>$<?php echo number_format($o['total'], 2); ?></td>
            <td><a href="/vuln-shop/orders.php?id=<?php echo $o['id']; ?>" class="btn btn-sm btn-primary">View</a></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php endif; ?>

<?php require_once 'includes/footer.php'; ?>
