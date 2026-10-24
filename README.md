# VulnShop

VulnShop is a deliberately vulnerable PHP and MySQL shop for **authorized, isolated security training**. It includes intentionally unsafe examples such as SQL injection, command injection, file inclusion, SSRF, XXE, and access-control flaws.

> **Lab use only. Do not deploy this application on the public internet or in production.** Run it on localhost or inside an isolated disposable lab. The PHP source and SQL seed data contain intentionally weak demonstration credentials and test data; never reuse them outside the lab.

## Setup

1. Use PHP 7.4+ with `mysqli` and MySQL 5.7+ or MariaDB 10+.
2. Create the `vulnshop` database and import `database.sql`.
3. Adjust the local database connection values in `includes/db.php` if needed.
4. Serve this directory locally and open `http://localhost/vuln-shop/`.

See [VULN-GUIDE.md](VULN-GUIDE.md) for the vulnerable routes, examples, and default lab accounts.
