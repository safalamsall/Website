<?php
// ============================================================
//  VulnShop - Open Redirect + HTTP Response Splitting
//  VULNERABILITIES:
//  - Open Redirect: 'url' param passed raw to Location header
//  - HTTP Response Splitting: CRLF injection via 'url' param
//  - Phishing via redirect: legitimate domain → attacker site
//  - Header injection: inject arbitrary HTTP headers
//  - Cache poisoning via header injection
// ============================================================
// NOTE: No page_title/header include here because we issue a redirect
// Only render page if not actually redirecting (demo mode)

session_start();
require_once 'includes/db.php';

$url     = isset($_GET['url'])     ? $_GET['url']     : '';
$action  = isset($_GET['action'])  ? $_GET['action']  : 'show';
$message = isset($_GET['message']) ? $_GET['message'] : '';

// VULNERABILITY: 'url' param used raw in header() — open redirect + CRLF injection
if ($action === 'go' && $url !== '') {
    // NO validation — redirect to any URL including http://evil.com
    // CRLF payload: /redirect.php?action=go&url=http://evil.com%0d%0aSet-Cookie:%20admin=true
    // This injects a Set-Cookie header via response splitting
    header("Location: $url");
    exit;
}

// HTTP Response Splitting demo (sets injected header without redirect)
if ($action === 'inject' && $message !== '') {
    // VULNERABILITY: $message injected into custom header raw
    // Payload: ?action=inject&message=hello%0d%0aSet-Cookie:%20hacked=yes%3bHttpOnly=false
    header("X-Message: $message");
    header("Content-Type: text/html");
}

$page_title = 'Redirect & Header Injection';
require_once 'includes/header.php';
?>

<div class="page-title">
    <h1><i class="fas fa-external-link-alt"></i> Open Redirect & Header Injection</h1>
    <span class="vuln-tag">Open Redirect / CRLF</span>
</div>

<div class="lab-hint">
    <h4><i class="fas fa-flask"></i> Vulnerabilities: Open Redirect + HTTP Response Splitting (CRLF Injection)</h4>
    <table>
        <tr><th>Attack</th><th>URL</th></tr>
        <tr><td>Open Redirect</td><td><code>/redirect.php?action=go&url=https://evil.com</code></td></tr>
        <tr><td>Phishing redirect</td><td><code>/redirect.php?action=go&url=https://evil.com/fake-login</code></td></tr>
        <tr><td>CRLF + Set-Cookie</td><td><code>/redirect.php?action=go&url=http://x.com%0d%0aSet-Cookie:%20admin=1</code></td></tr>
        <tr><td>CRLF + XSS via header</td><td><code>/redirect.php?action=go&url=http://x%0d%0aContent-Type:%20text/html%0d%0a%0d%0a&lt;script&gt;alert(1)&lt;/script&gt;</code></td></tr>
        <tr><td>Header injection</td><td><code>/redirect.php?action=inject&message=test%0d%0aX-Injected:%20hacked</code></td></tr>
        <tr><td>Cache poisoning</td><td><code>/redirect.php?action=inject&message=ok%0d%0aCache-Control:%20public,max-age=99999</code></td></tr>
        <tr><td>Internal redirect</td><td><code>/redirect.php?action=go&url=http://127.0.0.1/vuln-shop/admin/</code></td></tr>
    </table>
</div>

<div class="two-col-layout">

    <!-- Open Redirect -->
    <div class="checkout-section">
        <h3><i class="fas fa-directions"></i> Open Redirect</h3>
        <p style="color:#64748b;font-size:0.88rem;margin-bottom:16px">
            This page redirects users to any URL without validation.
            Used in phishing to abuse trusted domains.
        </p>
        <form method="GET">
            <input type="hidden" name="action" value="go">
            <div class="form-group">
                <label>Redirect to URL <small style="color:#e74c3c">(no whitelist — redirect anywhere)</small></label>
                <input type="text" name="url" class="form-control"
                       value="<?php echo htmlspecialchars($url); ?>"
                       placeholder="https://evil.com">
            </div>
            <button type="submit" class="btn btn-danger">
                <i class="fas fa-arrow-right"></i> Redirect Now
            </button>
        </form>

        <div style="margin-top:16px">
            <h4>Try These:</h4>
            <div style="display:flex;flex-direction:column;gap:6px;margin-top:8px;font-size:0.83rem">
                <a href="redirect.php?action=go&url=https://google.com" class="btn btn-sm btn-outline">→ google.com (legit)</a>
                <a href="redirect.php?action=go&url=https://evil.com" class="btn btn-sm btn-danger">→ evil.com (phishing)</a>
                <a href="redirect.php?action=go&url=http://127.0.0.1/vuln-shop/admin/" class="btn btn-sm btn-danger">→ Internal Admin</a>
            </div>
        </div>

        <div class="lab-hint" style="margin-top:16px">
            <h4>Phishing PoC</h4>
            <p>Send this URL to a victim — it appears to come from a trusted domain:</p>
            <code>http://localhost/vuln-shop/redirect.php?action=go&url=http://attacker.com/fake-login</code>
        </div>
    </div>

    <!-- CRLF / Header Injection -->
    <div class="checkout-section">
        <h3><i class="fas fa-code"></i> HTTP Response Splitting (CRLF)</h3>
        <p style="color:#64748b;font-size:0.88rem;margin-bottom:16px">
            Inject <code>%0d%0a</code> (CRLF) into the URL or message to add arbitrary HTTP headers.
        </p>
        <form method="GET">
            <input type="hidden" name="action" value="inject">
            <div class="form-group">
                <label>Header Value <small style="color:#e74c3c">(injected raw into X-Message header)</small></label>
                <input type="text" name="message" class="form-control"
                       value="<?php echo htmlspecialchars($message); ?>"
                       placeholder="hello%0d%0aSet-Cookie: hacked=yes">
            </div>
            <button type="submit" class="btn btn-warning">
                <i class="fas fa-code"></i> Inject Header
            </button>
        </form>

        <div style="margin-top:16px">
            <h4>Inject These (URL-encoded):</h4>
            <div style="display:flex;flex-direction:column;gap:6px;margin-top:8px;font-size:0.83rem">
                <a href="redirect.php?action=inject&message=ok%0d%0aSet-Cookie:%20admin=true" class="btn btn-sm btn-danger">Inject Set-Cookie: admin=true</a>
                <a href="redirect.php?action=inject&message=ok%0d%0aX-Hacked:%20by-crlf" class="btn btn-sm btn-warning">Inject X-Hacked header</a>
                <a href="redirect.php?action=inject&message=ok%0d%0aContent-Security-Policy:%20default-src%20*" class="btn btn-sm btn-warning">Disable CSP</a>
            </div>
        </div>

        <?php if ($message): ?>
        <div class="alert alert-warning" style="margin-top:16px">
            <strong>Header set:</strong> <code>X-Message: <?php echo htmlspecialchars($message); ?></code><br>
            <small>Check your browser DevTools → Network → Response Headers to see injected headers.</small>
        </div>
        <?php endif; ?>
    </div>

</div>

<?php require_once 'includes/footer.php'; ?>
