
<?php
// ============================================================
//  VulnShop - Homepage
//  VULNERABILITIES:
//  - SQLi via 'category' GET parameter (integer not validated)
//  - SQLi via 'sort' GET parameter injected directly into ORDER BY
//  - XSS via category name reflected without escaping
// ============================================================
$page_title = 'Home';
require_once 'includes/header.php';

// VULNERABILITY: 'category' not cast/sanitised before use in query
$category = isset($_GET['category']) ? $_GET['category'] : '';

// VULNERABILITY: 'sort' injected directly into ORDER BY clause
$sort = isset($_GET['sort']) ? $_GET['sort'] : 'id';

// Fetch categories for sidebar
$categories = db_fetch_all("SELECT * FROM categories");

// Build product query
if ($category !== '') {
    // VULNERABILITY: $category injected raw into SQL
    $sql = "SELECT p.*, c.name as cat_name FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE p.category_id = $category
            ORDER BY p.$sort";
} else {
    // VULNERABILITY: $sort injected raw into ORDER BY
    $sql = "SELECT p.*, c.name as cat_name FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            ORDER BY p.$sort";
}

$products = db_fetch_all($sql);

// Featured products (top 6 for hero section)
$featured = db_fetch_all("SELECT * FROM products ORDER BY id DESC LIMIT 6");
?>

<!-- Hero Banner -->
<div class="hero" style="margin: -20px -20px 30px -20px;">
    <div class="hero-content">
        <h1>Welcome to <span>VulnShop</span></h1>
        <p>Your one-stop shop for everything you need — and a playground for security testing.</p>
        <a href="/vuln-shop/search.php" class="btn btn-primary btn-lg">Shop Now</a>
        <a href="/vuln-shop/register.php" class="btn btn-outline btn-lg">Sign Up</a>
    </div>
</div>

<!-- Category Pills -->
<section class="section">
    <h2 class="section-title">Browse by Category</h2>
    <div class="category-pills">
        <a href="/vuln-shop/index.php" class="pill <?php echo $category === '' ? 'active' : ''; ?>">All</a>
        <?php foreach ($categories as $cat): ?>
            <!-- VULNERABILITY: cat name echoed without htmlspecialchars -->
            <a href="/vuln-shop/index.php?category=<?php echo $cat['id']; ?>"
               class="pill <?php echo $category == $cat['id'] ? 'active' : ''; ?>">
                <?php echo $cat['name']; ?>
            </a>
        <?php endforeach; ?>
    </div>
</section>

<!-- Sort Controls -->
<div class="sort-bar">
    <span>Sort by:</span>
    <!-- VULNERABILITY: sort value reflected in selected without escaping -->
    <a href="?category=<?php echo $category; ?>&sort=id"    class="sort-link <?php echo $sort=='id'?'active':''; ?>">Newest</a>
    <a href="?category=<?php echo $category; ?>&sort=price" class="sort-link <?php echo $sort=='price'?'active':''; ?>">Price</a>
    <a href="?category=<?php echo $category; ?>&sort=name"  class="sort-link <?php echo $sort=='name'?'active':''; ?>">Name</a>
    <span class="results-count"><?php echo count($products); ?> products found</span>
</div>

<!-- Product Grid -->
<section class="section">
    <?php if (empty($products)): ?>
        <div class="empty-state">
            <i class="fas fa-box-open"></i>
            <p>No products found.</p>
        </div>
    <?php else: ?>
    <div class="product-grid">
        <?php foreach ($products as $product): ?>
        <div class="product-card">
            <a href="/vuln-shop/product.php?id=<?php echo $product['id']; ?>">
                <div class="product-img-wrap">
                    <img src="/vuln-shop/images/<?php echo $product['image']; ?>"
                         onerror="this.src='/vuln-shop/images/placeholder.png'"
                         alt="<?php echo $product['name']; ?>">
                    <?php if ($product['stock'] < 10): ?>
                        <span class="badge-low">Low Stock</span>
                    <?php endif; ?>
                </div>
            </a>
            <div class="product-info">
                <!-- VULNERABILITY: product name output without escaping -->
                <h3><a href="/vuln-shop/product.php?id=<?php echo $product['id']; ?>"><?php echo $product['name']; ?></a></h3>
                <p class="cat-label"><?php echo $product['cat_name']; ?></p>
                <p class="product-desc"><?php echo substr($product['description'], 0, 80); ?>...</p>
                <div class="product-footer">
                    <span class="price">$<?php echo number_format($product['price'], 2); ?></span>
                    <a href="/vuln-shop/cart.php?action=add&product_id=<?php echo $product['id']; ?>"
                       class="btn btn-sm btn-primary">
                        <i class="fas fa-cart-plus"></i> Add to Cart
                    </a>
                </div>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
</section>

<!-- Info Banners -->
<section class="info-banners">
    <div class="info-card">
        <i class="fas fa-shipping-fast"></i>
        <h4>Free Shipping</h4>
        <p>On orders over $50</p>
    </div>
    <div class="info-card">
        <i class="fas fa-lock"></i>
        <h4>Secure Payment</h4>
        <p>(not really — this is a lab)</p>
    </div>
    <div class="info-card">
        <i class="fas fa-undo"></i>
        <h4>Easy Returns</h4>
        <p>30-day return policy</p>
    </div>
    <div class="info-card">
        <i class="fas fa-headset"></i>
        <h4>24/7 Support</h4>
        <p>Always here to help</p>
    </div>
</section>

<?php require_once 'includes/footer.php'; ?>
