<?php
// ============================================================
//  VulnShop - Registration Page
//  VULNERABILITIES:
//  - SQLi: all fields injected raw into INSERT query
//  - Stored XSS: username/bio stored raw, echoed everywhere
//  - No password hashing (plain text stored)
//  - No email validation
//  - No duplicate username check (or it's bypassable)
//  - Mass assignment: role can be set via hidden field manipulation
// ============================================================
$page_title = 'Register';
require_once 'includes/header.php';

$error   = '';
$success = '';
$form    = ['username'=>'','email'=>'','full_name'=>'','phone'=>''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username  = $_POST['username'];
    $password  = $_POST['password'];
    $email     = $_POST['email'];
    $full_name = $_POST['full_name'];
    $phone     = $_POST['phone'] ?? '';
    $bio       = $_POST['bio']   ?? '';

    // VULNERABILITY: role taken from hidden POST field — mass assignment
    // An attacker can set role=admin by modifying the form
    $role = isset($_POST['role']) ? $_POST['role'] : 'user';

    $form = compact('username', 'email', 'full_name', 'phone');

    if (empty($username) || empty($password) || empty($email)) {
        $error = 'Username, password and email are required.';
    } else {
        // VULNERABILITY: no duplicate check, all fields raw in SQL
        // Stored XSS: set username to <script>alert(document.cookie)</script>
        $sql = "INSERT INTO users (username, password, email, full_name, phone, bio, role)
                VALUES ('$username', '$password', '$email', '$full_name', '$phone', '$bio', '$role')";
        $new_id = db_insert($sql);

        if ($new_id) {
            $_SESSION['user_id']  = $new_id;
            $_SESSION['username'] = $username;
            $_SESSION['role']     = $role;
            $_SESSION['email']    = $email;

            $_SESSION['flash_msg']  = "Account created! Welcome, $username!";
            $_SESSION['flash_type'] = 'success';
            header('Location: /vuln-shop/index.php');
            exit;
        } else {
            $error = 'Registration failed. Please try again.';
        }
    }
}
?>

<div class="auth-wrap">
    <div class="auth-card auth-card-wide">
        <div class="auth-header">
            <i class="fas fa-user-plus"></i>
            <h2>Create Account</h2>
            <p>Join VulnShop today</p>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo $error; ?></div>
        <?php endif; ?>

        <!-- VULNERABILITY: no CSRF token -->
        <form method="POST" class="auth-form">
            <!-- VULNERABILITY: hidden role field — mass assignment -->
            <input type="hidden" name="role" value="user">

            <div class="form-row">
                <div class="form-group">
                    <label><i class="fas fa-user"></i> Username *</label>
                    <input type="text" name="username" class="form-control"
                           value="<?php echo $form['username']; ?>"
                           placeholder="Choose a username">
                </div>
                <div class="form-group">
                    <label><i class="fas fa-lock"></i> Password *</label>
                    <input type="password" name="password" class="form-control"
                           placeholder="Choose a password">
                </div>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label><i class="fas fa-envelope"></i> Email *</label>
                    <input type="text" name="email" class="form-control"
                           value="<?php echo $form['email']; ?>"
                           placeholder="your@email.com">
                </div>
                <div class="form-group">
                    <label><i class="fas fa-id-card"></i> Full Name</label>
                    <input type="text" name="full_name" class="form-control"
                           value="<?php echo $form['full_name']; ?>"
                           placeholder="John Doe">
                </div>
            </div>

            <div class="form-group">
                <label><i class="fas fa-phone"></i> Phone</label>
                <input type="text" name="phone" class="form-control"
                       value="<?php echo $form['phone']; ?>"
                       placeholder="555-0000">
            </div>

            <div class="form-group">
                <label><i class="fas fa-info-circle"></i> Bio
                    <small style="color:#e74c3c">(stored XSS vector — HTML accepted)</small>
                </label>
                <textarea name="bio" rows="3" class="form-control"
                          placeholder="Tell us about yourself... HTML is allowed here!"></textarea>
            </div>

            <button type="submit" class="btn btn-primary btn-block">
                <i class="fas fa-user-plus"></i> Create Account
            </button>
        </form>

        <div class="auth-footer">
            <p>Already have an account? <a href="/vuln-shop/login.php">Login here</a></p>
        </div>

        <!-- Lab hints -->
        <div class="lab-hint">
            <h4><i class="fas fa-flask"></i> Lab Hints</h4>
            <table>
                <tr><th>Vulnerability</th><th>How to Test</th></tr>
                <tr><td>Stored XSS</td><td>Set username or bio to <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></td></tr>
                <tr><td>SQLi (INSERT)</td><td>username: <code>test', 'pass', 'x@x.com', '', '', '', 'admin')--</code></td></tr>
                <tr><td>Mass Assignment</td><td>Add <code>role=admin</code> to POST body</td></tr>
                <tr><td>No password hash</td><td>Check the users table — passwords stored in plain text</td></tr>
            </table>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>
