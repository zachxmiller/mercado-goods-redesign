-- Discount/Promo codes
CREATE TABLE discounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  type TEXT NOT NULL, -- 'percentage', 'fixed_amount', 'free_shipping', 'bogo'
  value REAL, -- percentage (e.g. 20 for 20%) or fixed amount in dollars
  min_order_amount REAL,
  max_uses INTEGER,
  used_count INTEGER DEFAULT 0,
  applies_to TEXT, -- 'all', 'specific_products'
  product_ids TEXT, -- JSON array of product IDs if applies_to = 'specific_products'
  starts_at TEXT,
  expires_at TEXT,
  active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Page view analytics
CREATE TABLE page_views (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  page TEXT NOT NULL,
  product_slug TEXT,
  referrer TEXT,
  user_agent TEXT,
  country TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

-- SEO metadata per page/product
CREATE TABLE seo_meta (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  page_type TEXT NOT NULL, -- 'page', 'product', 'blog'
  page_identifier TEXT NOT NULL, -- slug or page name
  meta_title TEXT,
  meta_description TEXT,
  og_image TEXT,
  UNIQUE(page_type, page_identifier)
);

-- Tax rates
CREATE TABLE tax_rates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  state TEXT NOT NULL,
  rate REAL NOT NULL, -- e.g. 0.0625 for 6.25%
  country TEXT DEFAULT 'US',
  active INTEGER DEFAULT 1
);

-- Customer notification log
CREATE TABLE notifications_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER,
  type TEXT NOT NULL, -- 'order_confirmation', 'shipping_notification', 'refund_notification'
  recipient_email TEXT NOT NULL,
  subject TEXT,
  sent_at TEXT DEFAULT (datetime('now')),
  status TEXT DEFAULT 'sent'
);

-- Refunds
CREATE TABLE refunds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  reason TEXT,
  stripe_refund_id TEXT,
  status TEXT DEFAULT 'pending', -- 'pending', 'processed', 'failed'
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (order_id) REFERENCES orders(id)
);

-- Inventory alerts config
CREATE TABLE inventory_alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  threshold INTEGER DEFAULT 3,
  notify_email TEXT,
  auto_sold_out INTEGER DEFAULT 1, -- auto-mark as sold_out when all sizes hit 0
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (product_id) REFERENCES products(id)
);

-- URL Redirects
CREATE TABLE redirects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_path TEXT UNIQUE NOT NULL,
  to_path TEXT NOT NULL,
  permanent INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Add SEO columns to existing products table
ALTER TABLE products ADD COLUMN meta_title TEXT;
ALTER TABLE products ADD COLUMN meta_description TEXT;

-- Add SEO columns to existing blog_posts table
ALTER TABLE blog_posts ADD COLUMN meta_title TEXT;
ALTER TABLE blog_posts ADD COLUMN meta_description TEXT;

-- Add refund tracking to orders
ALTER TABLE orders ADD COLUMN refunded INTEGER DEFAULT 0;
ALTER TABLE orders ADD COLUMN refund_amount REAL DEFAULT 0;

-- Seed some default tax rates for common states
INSERT INTO tax_rates (state, rate) VALUES ('IL', 0.0625);
INSERT INTO tax_rates (state, rate) VALUES ('CA', 0.0725);
INSERT INTO tax_rates (state, rate) VALUES ('TX', 0.0625);
INSERT INTO tax_rates (state, rate) VALUES ('NY', 0.08);
INSERT INTO tax_rates (state, rate) VALUES ('FL', 0.06);

-- Set up default inventory alerts for all existing products
INSERT INTO inventory_alerts (product_id, threshold, auto_sold_out) VALUES (1, 3, 1);
INSERT INTO inventory_alerts (product_id, threshold, auto_sold_out) VALUES (2, 3, 1);
INSERT INTO inventory_alerts (product_id, threshold, auto_sold_out) VALUES (3, 3, 1);
INSERT INTO inventory_alerts (product_id, threshold, auto_sold_out) VALUES (4, 3, 1);
