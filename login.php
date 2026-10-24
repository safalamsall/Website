<?php
// ============================================================
//  VulnShop - Login Page
//  VULNERABILITIES:
//  - SQLi: username/password injected raw into SELECT query
//  - Authentication bypass: ' OR '1'='1 works
//  - XSS: error messages reflected without escaping
//  - No brute-force protection / rate limiting
//  - Session fixation: session not regenerated after login
//  - Credentials stored in plain text in DB
// ============================================================
$page_title = 'Login';
require_once 'includes/header.php';

$error = '';
$username_val = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // VULNERABILITY: raw user input directly in SQL — classic SQLi
    $username = $_POST['username'];
    $password = $_POST['password'];
    $username_val = $username;

    // VULNERABILITY: no hashing, plain text password comparison in SQL
    // Bypass: username = admin'-- or password = ' OR '1'='1
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $user = db_fetch_one($sql);

    if ($user) {
        // VULNERABILITY: no session_regenerate_id() — session fixation
        $_SESSION['user_id']  = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role']     = $user['role'];
        $_SESSION['email']    = $user['email'];

        // VULNERABILITY: flash message stored raw (XSS via username)
        $_SESSION['flash_msg']  = "Welcome back, " . $user['username'] . "!";
        $_SESSION['flash_type'] = 'success';

        if ($user['role'] === 'admin') {
            header('Location: /vuln-shop/admin/index.php');
        } else {
            header('Location: /vuln-shop/index.php');
        }
        exit;
    } else {
        // VULNERABILITY: error message reveals that username/password was wrong
        // — could be split to enumerate valid usernames
        $error = "Invalid username or password for user: <b>$username</b>";
    }
}
?>

<div class="auth-wrap">
    <div class="auth-card">
        <div class="auth-header">
            <i class="fas fa-user-circle"></i>
            <h2>Sign In</h2>
            <p>Welcome back to VulnShop</p>
        </div>

        <?php if ($error): ?>
            <!-- VULNERABILITY: $error echoed raw — reflected XSS via username field -->
            <div class="alert alert-danger"><?php echo $error; ?></div>
        <?php endif; ?>

        <!-- VULNERABILITY: no CSRF token on login form -->
        <form method="POST" class="auth-form">
            <div class="form-group">
                <label><i class="fas fa-user"></i> Username</label>
                <!-- VULNERABILITY: value reflected raw -->
                <input type="text" name="username" class="form-control"
                       value="<?php echo $username_val; ?>"
                       placeholder="Enter username" required>
            </div>
            <div class="form-group">
                <label><i class="fas fa-lock"></i> Password</label>
                <input type="password" name="password" class="form-control"
                       placeholder="Enter password" required>
            </div>
            <button type="submit" class="btn btn-primary btn-block">
                <i class="fas fa-sign-in-alt"></i> Login
            </button>
        </form>

        <div class="auth-footer">
            <p>Don't have an account? <a href="/vuln-shop/register.php">Register here</a></p>
        </div>

        <!-- Lab hint box -->
        <div class="lab-hint">
            <h4><i class="fas fa-flask"></i> Lab Hints</h4>
            <table>
                <tr><th>Test</th><th>Payload (username field)</th></tr>
                <tr><td>Auth Bypass</td><td><code>admin'--</code></td></tr>
                <tr><td>Auth Bypass 2</td><td><code>' OR '1'='1'--</code></td></tr>
                <tr><td>Union SQLi</td><td><code>' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--</code></td></tr>
                <tr><td>Reflected XSS</td><td><code>&lt;script&gt;alert(1)&lt;/script&gt;</code></td></tr>
            </table>
            <h4 style="margin-top:10px">Demo Accounts</h4>
            <table>
                <tr><th>Username</th><th>Password</th><th>Role</th></tr>
                <tr><td>admin</td><td>admin123</td><td>Admin</td></tr>
                <tr><td>john</td><td>password</td><td>User</td></tr>
                <tr><td>alice</td><td>alice123</td><td>User</td></tr>
            </table>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>
