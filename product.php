<?php
// ============================================================
//  VulnShop - Product Detail Page
//  VULNERABILITIES:
//  - SQLi: product id injected raw into SELECT query
//  - XSS (Reflected): product name/description echoed raw
//  - XSS (Stored): review comments stored & echoed without sanitisation
//  - Missing auth check on review submission
// ============================================================
$page_title = 'Product';
require_once 'includes/header.php';

// VULNERABILITY: No intval(), raw $_GET['id'] in SQL query
$id = isset($_GET['id']) ? $_GET['id'] : '1';

$product = db_fetch_one("SELECT p.*, c.name as cat_name
                         FROM products p
                         LEFT JOIN categories c ON p.category_id = c.id
                         WHERE p.id = $id");

if (!$product) {
    echo '<div class="alert alert-danger">Product not found. <a href="index.php">Go back</a></div>';
    require_once 'includes/footer.php';
    exit;
}

$page_title = $product['name'];

// Handle review submission
$review_error = '';
$review_success = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_review'])) {
    $rating  = $_POST['rating'];
    $comment = $_POST['comment'];  // VULNERABILITY: stored as-is, no sanitisation
    $user_id = isset($_SESSION['user_id']) ? $_SESSION['user_id'] : 0;
    $prod_id = $id; // still raw

    if (empty($comment)) {
        $review_error = 'Comment cannot be empty.';
    } else {
        // VULNERABILITY: all values injected raw into INSERT
        db_insert("INSERT INTO reviews (product_id, user_id, rating, comment)
                   VALUES ($prod_id, $user_id, $rating, '$comment')");
        $review_success = 'Review posted successfully!';
    }
}

// Fetch reviews - no escaping on output
$reviews = db_fetch_all("SELECT r.*, u.username FROM reviews r
                         LEFT JOIN users u ON r.user_id = u.id
                         WHERE r.product_id = $id
                         ORDER BY r.created_at DESC");

// Related products
$related = db_fetch_all("SELECT * FROM products
                         WHERE category_id = {$product['category_id']}
                         AND id != $id
                         LIMIT 4");
?>

<div class="breadcrumb">
    <a href="/vuln-shop/index.php">Home</a> &rsaquo;
    <a href="/vuln-shop/search.php?category=<?php echo $product['category_id']; ?>"><?php echo $product['cat_name']; ?></a> &rsaquo;
    <!-- VULNERABILITY: product name reflected without escaping -->
    <span><?php echo $product['name']; ?></span>
</div>

<div class="product-detail-wrap">
    <!-- Product Images -->
    <div class="product-detail-img">
        <img src="/vuln-shop/images/<?php echo $product['image']; ?>"
             onerror="this.src='/vuln-shop/images/placeholder.png'"
             alt="<?php echo $product['name']; ?>"
             class="main-img">
    </div>

    <!-- Product Info -->
    <div class="product-detail-info">
        <!-- VULNERABILITY: name & description echoed raw (XSS if data tampered) -->
        <h1 class="product-title"><?php echo $product['name']; ?></h1>
        <p class="product-category"><i class="fas fa-tag"></i> <?php echo $product['cat_name']; ?></p>
        <div class="price-large">$<?php echo number_format($product['price'], 2); ?></div>

        <div class="stock-info">
            <?php if ($product['stock'] > 0): ?>
                <span class="in-stock"><i class="fas fa-check-circle"></i> In Stock (<?php echo $product['stock']; ?> left)</span>
            <?php else: ?>
                <span class="out-stock"><i class="fas fa-times-circle"></i> Out of Stock</span>
            <?php endif; ?>
        </div>

        <div class="product-description">
            <!-- VULNERABILITY: description echoed raw -->
            <p><?php echo $product['description']; ?></p>
        </div>

        <!-- Add to Cart Form - VULNERABILITY: no CSRF token -->
        <form action="/vuln-shop/cart.php" method="POST" class="add-to-cart-form">
            <input type="hidden" name="product_id" value="<?php echo $product['id']; ?>">
            <div class="qty-wrap">
                <label>Quantity:</label>
                <input type="number" name="quantity" value="1" min="1" max="99" class="qty-input">
            </div>
            <button type="submit" name="add_to_cart" class="btn btn-primary btn-lg">
                <i class="fas fa-cart-plus"></i> Add to Cart
            </button>
            <a href="/vuln-shop/checkout.php" class="btn btn-success btn-lg">
                <i class="fas fa-bolt"></i> Buy Now
            </a>
        </form>

        <div class="product-meta">
            <p><strong>Product ID:</strong> <?php echo $product['id']; ?></p>
            <p><strong>Category:</strong> <?php echo $product['cat_name']; ?></p>
        </div>
    </div>
</div>

<!-- Reviews Section -->
<section class="reviews-section">
    <h2>Customer Reviews (<?php echo count($reviews); ?>)</h2>

    <?php if ($review_error): ?>
        <div class="alert alert-danger"><?php echo $review_error; ?></div>
    <?php endif; ?>
    <?php if ($review_success): ?>
        <div class="alert alert-success"><?php echo $review_success; ?></div>
    <?php endif; ?>

    <!-- Review Form - no CSRF, no auth required -->
    <div class="review-form-wrap">
        <h3>Write a Review</h3>
        <!-- VULNERABILITY: no CSRF token, no login required -->
        <form method="POST" class="review-form">
            <div class="form-group">
                <label>Rating:</label>
                <select name="rating" class="form-control">
                    <option value="5">⭐⭐⭐⭐⭐ (5)</option>
                    <option value="4">⭐⭐⭐⭐ (4)</option>
                    <option value="3">⭐⭐⭐ (3)</option>
                    <option value="2">⭐⭐ (2)</option>
                    <option value="1">⭐ (1)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Comment: <small style="color:#e74c3c">(HTML allowed — stored XSS vector)</small></label>
                <!-- VULNERABILITY: raw HTML accepted and stored -->
                <textarea name="comment" rows="4" class="form-control"
                          placeholder="Write your review here... <script>alert(1)</script> is also valid ;)"></textarea>
            </div>
            <button type="submit" name="submit_review" class="btn btn-primary">Post Review</button>
        </form>
    </div>

    <!-- Display Reviews -->
    <div class="reviews-list">
        <?php if (empty($reviews)): ?>
            <p class="no-reviews">No reviews yet. Be the first!</p>
        <?php else: ?>
            <?php foreach ($reviews as $review): ?>
            <div class="review-card">
                <div class="review-header">
                    <strong><?php echo $review['username'] ?? 'Guest'; ?></strong>
                    <span class="review-stars">
                        <?php echo str_repeat('⭐', (int)$review['rating']); ?>
                    </span>
                    <span class="review-date"><?php echo $review['created_at']; ?></span>
                </div>
                <!-- VULNERABILITY: comment echoed raw — stored XSS -->
                <div class="review-comment"><?php echo $review['comment']; ?></div>
            </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
</section>

<!-- Related Products -->
<?php if (!empty($related)): ?>
<section class="section">
    <h2 class="section-title">Related Products</h2>
    <div class="product-grid">
        <?php foreach ($related as $p): ?>
        <div class="product-card">
            <a href="/vuln-shop/product.php?id=<?php echo $p['id']; ?>">
                <div class="product-img-wrap">
                    <img src="/vuln-shop/images/<?php echo $p['image']; ?>"
                         onerror="this.src='/vuln-shop/images/placeholder.png'"
                         alt="<?php echo $p['name']; ?>">
                </div>
            </a>
            <div class="product-info">
                <h3><a href="/vuln-shop/product.php?id=<?php echo $p['id']; ?>"><?php echo $p['name']; ?></a></h3>
                <div class="product-footer">
                    <span class="price">$<?php echo number_format($p['price'], 2); ?></span>
                    <a href="/vuln-shop/cart.php?action=add&product_id=<?php echo $p['id']; ?>" class="btn btn-sm btn-primary">Add</a>
                </div>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
</section>
<?php endif; ?>

<?php require_once 'includes/footer.php'; ?>
