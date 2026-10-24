<?php
// ============================================================
//  VulnShop - Password Reset
//  VULNERABILITIES:
//  - Predictable reset token: md5(username + date('Y-m-d'))
//  - Token never expires (no expiry column)
//  - Token stored in users table in plain text
//  - No rate limiting on reset requests
//  - Username enumeration: different responses for valid/invalid users
//  - Token accepted via GET (leaks in Referer/logs)
//  - New password stored in plain text
//  - No old password required to reset
// ============================================================
$page_title = 'Password Reset';
require_once 'includes/header.php';

// Ensure reset_token column exists (add on first visit)
db_query("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR(64) DEFAULT NULL");
db_query("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expiry DATETIME DEFAULT NULL");

$step    = isset($_GET['step'])  ? $_GET['step']  : '1';
$msg     = '';
$error   = '';

// ---- STEP 1: Request reset ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['request_reset'])) {
    $username = $_POST['username'];

    // VULNERABILITY: username injected raw into query
    $user = db_fetch_one("SELECT * FROM users WHERE username = '$username'");

    if ($user) {
        // VULNERABILITY: predictable token — md5(username + today's date)
        // Attacker who knows the username can compute token without server interaction
        $token = md5($username . date('Y-m-d'));

        // VULNERABILITY: no expiry stored — token valid forever
        db_query("UPDATE users SET reset_token = '$token' WHERE username = '$username'");

        // VULNERABILITY: token exposed directly on screen (should be emailed)
        $msg = "Reset token generated (in real app this would be emailed):<br>
                <div style='background:#1e293b;color:#a5f3fc;padding:10px;border-radius:6px;font-family:monospace;margin-top:8px;word-break:break-all'>
                    <a href='reset_password.php?step=2&token=$token&user=$username' style='color:#a5f3fc'>
                        http://localhost/vuln-shop/reset_password.php?step=2&amp;token=$token&amp;user=$username
                    </a>
                </div>";
    } else {
        // VULNERABILITY: different message confirms username does NOT exist (enumeration)
        $error = "No account found with username: <strong>$username</strong>";
    }
}

// ---- STEP 2: Validate token + set new password ----
if ($step === '2') {
    $token_in = isset($_GET['token']) ? $_GET['token'] : '';
    $user_in  = isset($_GET['user'])  ? $_GET['user']  : '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['do_reset'])) {
        $new_pass  = $_POST['new_password'];
        $token_in  = $_POST['token'];
        $user_in   = $_POST['user'];

        // VULNERABILITY: token and user both from POST, raw in SQL
        $user = db_fetch_one("SELECT * FROM users WHERE username='$user_in' AND reset_token='$token_in'");

        if ($user) {
            // VULNERABILITY: new password stored plain text, no hashing
            db_query("UPDATE users SET password='$new_pass', reset_token=NULL WHERE username='$user_in'");
            $msg = "Password reset successfully for <strong>$user_in</strong>!
                    <a href='login.php'>Login now</a>";
        } else {
            // VULNERABILITY: also guessable — try md5(username+Y-m-d)
            $expected = md5($user_in . date('Y-m-d'));
            if ($token_in === $expected) {
                db_query("UPDATE users SET password='$new_pass' WHERE username='$user_in'");
                $msg = "Password reset via predicted token for <strong>$user_in</strong>!";
            } else {
                $error = 'Invalid or expired token.';
            }
        }
    }
}
?>

<div class="page-title">
    <h1><i class="fas fa-key"></i> Password Reset</h1>
    <span class="vuln-tag">Broken Password Reset</span>
</div>

<div class="lab-hint">
    <h4><i class="fas fa-flask"></i> Vulnerabilities: Broken Password Reset</h4>
    <table>
        <tr><th>Vulnerability</th><th>Detail</th></tr>
        <tr><td>Predictable token</td>    <td><code>md5(username + date('Y-m-d'))</code> &mdash; brute-forceable without server access</td></tr>
        <tr><td>Token never expires</td>  <td>No expiry column &mdash; old tokens stay valid forever</td></tr>
        <tr><td>Username enumeration</td> <td>Error message reveals whether username exists</td></tr>
        <tr><td>Token in URL</td>         <td>Token leaks in browser history, Referer, server logs</td></tr>
        <tr><td>No rate limiting</td>     <td>Unlimited reset requests, no CAPTCHA</td></tr>
        <tr><td>Token shown on page</td>  <td>Token displayed instead of emailed (demo convenience)</td></tr>
        <tr><td>Plain-text password</td>  <td>New password stored without hashing</td></tr>
    </table>
    <p style="margin-top:8px"><strong>Exploit:</strong> For username <code>admin</code>, compute token as:</p>
    <code>php -r "echo md5('admin' . date('Y-m-d'));"</code>
    <p style="margin-top:6px">Then visit: <code>/reset_password.php?step=2&amp;token=COMPUTED&amp;user=admin</code></p>
</div>

<?php if ($msg):   echo '<div class="alert alert-success" style="margin-bottom:16px">'.$msg.'</div>'; endif; ?>
<?php if ($error): echo '<div class="alert alert-danger"  style="margin-bottom:16px">'.$error.'</div>'; endif; ?>

<?php if ($step === '1'): ?>

<div class="auth-wrap">
    <div class="auth-card">
        <div class="auth-header">
            <i class="fas fa-unlock-alt"></i>
            <h2>Reset Password</h2>
            <p>Enter your username to get a reset link</p>
        </div>
        <!-- VULNERABILITY: no CSRF token -->
        <form method="POST" class="auth-form">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control" placeholder="admin">
            </div>
            <button type="submit" name="request_reset" class="btn btn-primary btn-block">
                <i class="fas fa-paper-plane"></i> Send Reset Link
            </button>
        </form>
        <div class="auth-footer">
            <p><a href="login.php">Back to login</a></p>
        </div>

        <div class="lab-hint" style="margin-top:16px">
            <h4>Token Prediction PoC</h4>
            <p>Predict token for any user without triggering the reset flow:</p>
            <code>md5("admin" + "<?php echo date('Y-m-d'); ?>")</code>
            <p style="margin-top:6px">= <strong><?php echo md5('admin'.date('Y-m-d')); ?></strong></p>
            <a href="reset_password.php?step=2&token=<?php echo md5('admin'.date('Y-m-d')); ?>&user=admin"
               class="btn btn-sm btn-danger" style="margin-top:8px">
                Reset admin password directly
            </a>
        </div>
    </div>
</div>

<?php else: ?>

<div class="auth-wrap">
    <div class="auth-card">
        <div class="auth-header">
            <i class="fas fa-lock-open"></i>
            <h2>Set New Password</h2>
        </div>
        <form method="POST" class="auth-form">
            <!-- VULNERABILITY: token and user passed via hidden fields (manipulable) -->
            <input type="hidden" name="token" value="<?php echo htmlspecialchars($token_in ?? ''); ?>">
            <input type="hidden" name="user"  value="<?php echo htmlspecialchars($user_in  ?? ''); ?>">
            <div class="form-group">
                <label>Username</label>
                <input type="text" class="form-control"
                       value="<?php echo htmlspecialchars($user_in ?? ''); ?>" disabled>
            </div>
            <div class="form-group">
                <label>New Password <small style="color:#e74c3c">(stored in plain text)</small></label>
                <input type="password" name="new_password" class="form-control" placeholder="New password">
            </div>
            <button type="submit" name="do_reset" class="btn btn-primary btn-block">
                <i class="fas fa-save"></i> Reset Password
            </button>
        </form>
    </div>
</div>

<?php endif; ?>

<?php require_once 'includes/footer.php'; ?>
