<?php
// ============================================================
//  VulnShop - Search / Product Listing Page
//  VULNERABILITIES:
//  - SQLi: search term 'q' injected raw into LIKE query
//  - SQLi: 'category', 'min_price', 'max_price', 'sort' injected raw
//  - XSS (Reflected): search term echoed raw in page and input value
//  - Information disclosure: SQL query shown on error
// ============================================================
$page_title = 'Search';
require_once 'includes/header.php';

// VULNERABILITY: all GET params used raw in SQL
$q         = isset($_GET['q'])         ? $_GET['q']         : '';
$category  = isset($_GET['category'])  ? $_GET['category']  : '';
$min_price = isset($_GET['min_price']) ? $_GET['min_price'] : '';
$max_price = isset($_GET['max_price']) ? $_GET['max_price'] : '';
$sort      = isset($_GET['sort'])      ? $_GET['sort']      : 'p.id DESC';

$categories = db_fetch_all("SELECT * FROM categories");

// Build SQL dynamically from unescaped inputs
$where = [];
$where[] = "1=1";

if ($q !== '') {
    // VULNERABILITY: $q raw in LIKE — SQLi + reflected XSS
    $where[] = "(p.name LIKE '%$q%' OR p.description LIKE '%$q%')";
}
if ($category !== '') {
    // VULNERABILITY: $category raw integer (not validated)
    $where[] = "p.category_id = $category";
}
if ($min_price !== '') {
    // VULNERABILITY: $min_price raw decimal
    $where[] = "p.price >= $min_price";
}
if ($max_price !== '') {
    $where[] = "p.price <= $max_price";
}

$where_clause = implode(' AND ', $where);

// VULNERABILITY: $sort injected raw into ORDER BY
$sql = "SELECT p.*, c.name as cat_name
        FROM products p
        LEFT JOIN categories c ON p.category_id = c.id
        WHERE $where_clause
        ORDER BY $sort";

$products = db_fetch_all($sql);
?>

<div class="search-page">
    <!-- Search Header -->
    <div class="search-header">
        <h1>
            <?php if ($q !== ''): ?>
                <!-- VULNERABILITY: $q echoed raw — reflected XSS -->
                Search results for: <em>"<?php echo $q; ?>"</em>
            <?php elseif ($category !== ''): ?>
                <?php
                $cat_info = db_fetch_one("SELECT name FROM categories WHERE id = $category");
                echo $cat_info ? $cat_info['name'] : 'Category';
                ?>
            <?php else: ?>
                All Products
            <?php endif; ?>
        </h1>
        <span class="results-count"><?php echo count($products); ?> results</span>
    </div>

    <div class="search-layout">
        <!-- Sidebar Filters -->
        <aside class="search-sidebar">
            <!-- VULNERABILITY: all filter values reflected raw into form inputs -->
            <form method="GET" class="filter-form">
                <h3>Filters</h3>

                <div class="form-group">
                    <label>Search</label>
                    <!-- VULNERABILITY: raw $q echoed into value attribute -->
                    <input type="text" name="q" class="form-control"
                           value="<?php echo $q; ?>"
                           placeholder="Search...">
                </div>

                <div class="form-group">
                    <label>Category</label>
                    <select name="category" class="form-control">
                        <option value="">All Categories</option>
                        <?php foreach ($categories as $cat): ?>
                            <option value="<?php echo $cat['id']; ?>"
                                <?php echo ($category == $cat['id']) ? 'selected' : ''; ?>>
                                <?php echo $cat['name']; ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="form-group">
                    <label>Min Price ($)</label>
                    <input type="text" name="min_price" class="form-control"
                           value="<?php echo $min_price; ?>"
                           placeholder="0">
                </div>

                <div class="form-group">
                    <label>Max Price ($)</label>
                    <input type="text" name="max_price" class="form-control"
                           value="<?php echo $max_price; ?>"
                           placeholder="9999">
                </div>

                <div class="form-group">
                    <label>Sort By</label>
                    <select name="sort" class="form-control">
                        <option value="p.id DESC">Newest</option>
                        <option value="p.price ASC"  <?php echo $sort=='p.price ASC'?'selected':'';?>>Price: Low to High</option>
                        <option value="p.price DESC" <?php echo $sort=='p.price DESC'?'selected':'';?>>Price: High to Low</option>
                        <option value="p.name ASC"   <?php echo $sort=='p.name ASC'?'selected':'';?>>Name A-Z</option>
                    </select>
                </div>

                <button type="submit" class="btn btn-primary btn-block">Apply Filters</button>
                <a href="/vuln-shop/search.php" class="btn btn-outline btn-block" style="margin-top:8px">Clear All</a>
            </form>

            <!-- Lab hints -->
            <div class="lab-hint" style="margin-top:20px">
                <h4><i class="fas fa-flask"></i> SQLi Payloads</h4>
                <p><strong>q param:</strong></p>
                <code>%' UNION SELECT 1,2,3,4,5,6,7,8--</code><br><br>
                <code>%' AND 1=2 UNION SELECT table_name,2,3,4,5,6,7,8 FROM information_schema.tables--</code><br><br>
                <p><strong>Reflected XSS:</strong></p>
                <code>&lt;img src=x onerror=alert(document.cookie)&gt;</code>
            </div>
        </aside>

        <!-- Product Results -->
        <div class="search-results">
            <?php if (empty($products)): ?>
                <div class="empty-state">
                    <i class="fas fa-search"></i>
                    <!-- VULNERABILITY: $q echoed raw again -->
                    <p>No products found for "<?php echo $q; ?>".</p>
                    <a href="/vuln-shop/search.php" class="btn btn-primary">Browse All</a>
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
                            </div>
                        </a>
                        <div class="product-info">
                            <!-- VULNERABILITY: product name raw -->
                            <h3><a href="/vuln-shop/product.php?id=<?php echo $product['id']; ?>"><?php echo $product['name']; ?></a></h3>
                            <p class="cat-label"><?php echo $product['cat_name']; ?></p>
                            <p class="product-desc"><?php echo substr(strip_tags($product['description']), 0, 80); ?>...</p>
                            <div class="product-footer">
                                <span class="price">$<?php echo number_format($product['price'], 2); ?></span>
                                <a href="/vuln-shop/cart.php?action=add&product_id=<?php echo $product['id']; ?>"
                                   class="btn btn-sm btn-primary">
                                    <i class="fas fa-cart-plus"></i> Add
                                </a>
                            </div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>
