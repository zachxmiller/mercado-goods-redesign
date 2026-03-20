-- Migration: 0001_initial
-- Mercado Goods e-commerce database schema + seed data

-- ============================================================
-- SCHEMA
-- ============================================================

-- Products
CREATE TABLE products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  description TEXT,
  price REAL NOT NULL,
  compare_at_price REAL,
  sizes TEXT,
  inventory TEXT,
  images TEXT,
  status TEXT DEFAULT 'active',
  category TEXT,
  position INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Orders
CREATE TABLE orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_number TEXT UNIQUE NOT NULL,
  customer_name TEXT NOT NULL,
  customer_email TEXT NOT NULL,
  customer_phone TEXT,
  shipping_address TEXT,
  items TEXT NOT NULL,
  subtotal REAL NOT NULL,
  shipping_cost REAL DEFAULT 0,
  total REAL NOT NULL,
  status TEXT DEFAULT 'pending',
  stripe_payment_id TEXT,
  stripe_session_id TEXT,
  tracking_number TEXT,
  carrier TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Blog posts
CREATE TABLE blog_posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  content TEXT,
  excerpt TEXT,
  image_url TEXT,
  published INTEGER DEFAULT 0,
  published_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Subscribers
CREATE TABLE subscribers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  phone TEXT,
  source TEXT DEFAULT 'website',
  subscribed INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Admin users
CREATE TABLE admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Page builder - stores website section configs
CREATE TABLE page_sections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  page TEXT NOT NULL DEFAULT 'home',
  section_type TEXT NOT NULL,
  position INTEGER DEFAULT 0,
  config TEXT NOT NULL,
  visible INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Site settings (global config like site name, colors, fonts, socials, etc)
CREATE TABLE site_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now'))
);

-- ============================================================
-- SEED DATA
-- ============================================================

-- Products
INSERT INTO products (name, slug, description, price, sizes, inventory, images, status, position) VALUES
(
  'La Camisa Blanca',
  'la-camisa-blanca',
  '100% US-grown cotton tee, oversized fit',
  50.00,
  '["S","M","L","XL","2XL","3XL"]',
  '{"S":5,"M":5,"L":5,"XL":5,"2XL":5,"3XL":5}',
  '["https://mercado-goods.com/cdn/shop/files/ambermilla204779-R1-023-10.jpg?v=1771633559&width=800","https://mercado-goods.com/cdn/shop/files/1_b955aade-a69f-46d1-bdc2-9ab3b8517de2.png?v=1771721671&width=800"]',
  'active',
  0
),
(
  'La Sudadera Negra',
  'la-sudadera-negra',
  'Oversized sweatshirt',
  90.00,
  '["S","M","L","XL","2XL"]',
  '{"S":0,"M":0,"L":0,"XL":0,"2XL":0}',
  '["https://mercado-goods.com/cdn/shop/files/ambermilla204779-R1-039-18.jpg?v=1771633613&width=800"]',
  'sold_out',
  1
),
(
  'El Gaban',
  'el-gaban',
  'Handmade Japanese raw selvedge denim poncho',
  150.00,
  '["One Size"]',
  '{"One Size":0}',
  '["https://mercado-goods.com/cdn/shop/files/IMG_0435.jpg?v=1771633732&width=800","https://mercado-goods.com/cdn/shop/files/1_dd3a755c-080e-4eae-aa01-b865cea4dd50.png?v=1771722854&width=800"]',
  'sold_out',
  2
),
(
  'La Tote Bag',
  'la-tote-bag',
  'Handcrafted tote bag',
  250.00,
  '["One Size"]',
  '{"One Size":0}',
  '["https://mercado-goods.com/cdn/shop/files/DSC_0314.jpg?v=1771724386&width=800"]',
  'sold_out',
  3
);

-- Blog posts
INSERT INTO blog_posts (title, slug, excerpt, image_url, published, published_at) VALUES
(
  'Why''s Our Last Showcase So Special?',
  'final-hurrah',
  'A labor of love — the story behind our most meaningful event yet.',
  'https://mercado-goods.com/cdn/shop/articles/ONE_Final_HUrrah-2.png?v=1747258478&width=600',
  1,
  '2025-05-15'
),
(
  'The Media Luna Interview',
  'media-luna-interview',
  'A conversation with Claudia about community, creativity, and building something bigger than yourself.',
  'https://mercado-goods.com/cdn/shop/articles/Media_Luna.png?v=1736796582&width=600',
  1,
  '2025-01-13'
),
(
  'Why Perfection Sucks',
  'why-perfection-sucks',
  'On creative block, embracing imperfection, and finding freedom in the process.',
  'https://mercado-goods.com/cdn/shop/articles/Perfection.png?v=1725278368&width=600',
  1,
  '2024-09-02'
);

-- Homepage sections
INSERT INTO page_sections (page, section_type, position, config, visible) VALUES
(
  'home',
  'hero',
  0,
  '{"heading":"Rooted in Heritage. Crafted with Intention.","subheading":"Small-batch goods celebrating Latino culture and craftsmanship.","cta_text":"Shop Now","cta_link":"/shop","background_image":""}',
  1
),
(
  'home',
  'marquee',
  1,
  '{"text":"FREE SHIPPING ON ORDERS OVER $100","speed":"normal","visible":true}',
  1
),
(
  'home',
  'products',
  2,
  '{"heading":"Our Goods","show_count":4,"layout":"grid"}',
  1
),
(
  'home',
  'indigo_sagrado',
  3,
  '{"heading":"Indigo Sagrado","description":"A heritage dyeing technique passed down through generations.","image_url":"","cta_text":"Learn More","cta_link":"/indigo-sagrado"}',
  1
),
(
  'home',
  'story',
  4,
  '{"heading":"Our Story","content":"Mercado Goods is a small-batch brand rooted in Latino heritage and crafted with intention.","image_url":"","cta_text":"Read More","cta_link":"/about"}',
  1
),
(
  'home',
  'journal',
  5,
  '{"heading":"The Journal","show_count":3}',
  1
),
(
  'home',
  'newsletter',
  6,
  '{"heading":"Join the Community","subheading":"Be the first to know about new drops, events, and stories.","placeholder":"Enter your email","button_text":"Subscribe"}',
  1
);

-- Site settings
INSERT INTO site_settings (key, value) VALUES
('site_name', 'Mercado Goods'),
('tagline', 'Rooted in Heritage. Crafted with Intention.'),
('logo_url', 'https://mercado-goods.com/cdn/shop/files/Gallo_design_width_22.5_Gallo_Design_Length-4.png?v=1739886113&width=300'),
('primary_color', '#cb6305'),
('background_color', '#0a0a0a'),
('text_color', '#f5eedd'),
('instagram', 'https://instagram.com/mercadogoods'),
('tiktok', 'https://tiktok.com/@mercadogoods'),
('youtube', 'https://youtube.com/@mercadogoods'),
('footer_text', 'Rooted in heritage and crafted with intention.');
