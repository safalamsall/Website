<?php
// ============================================================
//  VulnShop - Database Connection (DELIBERATELY VULNERABLE)
//  - Credentials hardcoded in plaintext
//  - No PDO / prepared statements used anywhere
//  - Errors displayed to user (information disclosure)
// ============================================================

define('DB_HOST', 'localhost');
define('DB_USER', 'root');       // change if needed
define('DB_PASS', 'root');       // change if needed
define('DB_NAME', 'vulnshop');

// Old-style mysql_* style via mysqli, no prepared statements
$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);

if (!$conn) {
    // VULNERABILITY: Full error message exposed to the browser
    die("<b>Database connection failed:</b> " . mysqli_connect_error());
}

// No charset set - potential charset-based SQLi
// mysqli_set_charset($conn, 'utf8');  <-- intentionally commented out

// Helper - runs a raw query and returns result (no sanitisation)
function db_query($sql) {
    global $conn;
    $result = mysqli_query($conn, $sql);
    if (!$result) {
        // VULNERABILITY: SQL errors exposed to the user
        echo "<div style='color:red;background:#fff3f3;padding:8px;margin:4px 0;border:1px solid red;font-family:monospace'>";
        echo "<b>[DB ERROR]</b> " . mysqli_error($GLOBALS['conn']);
        echo "<br><b>[QUERY]</b> " . htmlspecialchars($sql);
        echo "</div>";
        return false;
    }
    return $result;
}

// Returns all rows as array
function db_fetch_all($sql) {
    $result = db_query($sql);
    if (!$result) return [];
    $rows = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $rows[] = $row;
    }
    return $rows;
}

// Returns single row
function db_fetch_one($sql) {
    $result = db_query($sql);
    if (!$result) return null;
    return mysqli_fetch_assoc($result);
}

// Returns insert ID after INSERT
function db_insert($sql) {
    global $conn;
    db_query($sql);
    return mysqli_insert_id($conn);
}
?>
