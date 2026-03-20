import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono();

// ─────────────────────────────────────────────
// CORS
// ─────────────────────────────────────────────
app.use('/api/*', cors());

// ─────────────────────────────────────────────
// CRYPTO HELPERS  (Web Crypto API — no npm deps)
// ─────────────────────────────────────────────

/** SHA-256 hash a plaintext password, return hex string */
async function hashPassword(password) {
  const data = new TextEncoder().encode(password);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Compare plaintext against stored hash */
async function verifyPassword(password, hash) {
  return (await hashPassword(password)) === hash;
}

/** Sign a JWT (HS256) using Web Crypto */
async function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const claims = { ...payload, iat: now, exp: now + 60 * 60 * 24 }; // 24h

  const encode = (obj) =>
    btoa(JSON.stringify(obj))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

  const headerB64 = encode(header);
  const payloadB64 = encode(claims);
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `${signingInput}.${sigB64}`;
}

/** Verify a JWT (HS256), return payload or null */
async function verifyJWT(token, secret) {
  try {
    const [headerB64, payloadB64, sigB64] = token.split('.');
    if (!headerB64 || !payloadB64 || !sigB64) return null;

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );

    // Restore base64 padding
    const pad = (s) => s + '='.repeat((4 - (s.length % 4)) % 4);
    const sigBytes = Uint8Array.from(atob(pad(sigB64).replace(/-/g, '+').replace(/_/g, '/')), (c) =>
      c.charCodeAt(0),
    );

    const signingInput = `${headerB64}.${payloadB64}`;
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      sigBytes,
      new TextEncoder().encode(signingInput),
    );
    if (!valid) return null;

    const payload = JSON.parse(atob(pad(payloadB64).replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────
// AUTH MIDDLEWARE (protects /api/admin/* except login & setup)
// ─────────────────────────────────────────────
app.use('/api/admin/*', async (c, next) => {
  const path = c.req.path;
  // Allow login and setup without auth
  if (path === '/api/admin/login' || path === '/api/admin/setup') {
    return next();
  }

  const auth = c.req.header('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const token = auth.slice(7);
  const payload = await verifyJWT(token, c.env.JWT_SECRET);
  if (!payload) {
    return c.json({ error: 'Invalid or expired token' }, 401);
  }

  c.set('user', payload);
  return next();
});

// ─────────────────────────────────────────────
// UTILITY HELPERS
// ─────────────────────────────────────────────

/** Generate a URL-safe slug, appending -2, -3, etc. if it already exists */
async function generateSlug(db, table, text, column = 'slug') {
  let base = text
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/[\s]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');

  let slug = base;
  let counter = 2;

  while (true) {
    const existing = await db
      .prepare(`SELECT id FROM ${table} WHERE ${column} = ?`)
      .bind(slug)
      .first();
    if (!existing) return slug;
    slug = `${base}-${counter}`;
    counter++;
  }
}

/** Generate next order number like MG-001, MG-002 */
async function generateOrderNumber(db) {
  const last = await db
    .prepare("SELECT order_number FROM orders ORDER BY id DESC LIMIT 1")
    .first();

  if (!last) return 'MG-001';

  const num = parseInt(last.order_number.replace('MG-', ''), 10);
  return `MG-${String(num + 1).padStart(3, '0')}`;
}

/** Standard JSON error response */
function jsonError(c, message, status = 400) {
  return c.json({ error: message }, status);
}

/** Guess content-type from file extension */
function contentTypeFromKey(key) {
  const ext = (key.split('.').pop() || '').toLowerCase();
  const map = {
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    png: 'image/png',
    gif: 'image/gif',
    webp: 'image/webp',
    svg: 'image/svg+xml',
    avif: 'image/avif',
    ico: 'image/x-icon',
    mp4: 'video/mp4',
    pdf: 'application/pdf',
  };
  return map[ext] || 'application/octet-stream';
}

// ═════════════════════════════════════════════
//  PUBLIC ROUTES
// ═════════════════════════════════════════════

// ── Products ─────────────────────────────────

/** GET /api/products — all non-draft products, ordered by position */
app.get('/api/products', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM products WHERE status != 'draft' ORDER BY position ASC, id ASC",
    ).all();
    return c.json(results);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** GET /api/products/:slug — single product by slug */
app.get('/api/products/:slug', async (c) => {
  try {
    const product = await c.env.DB.prepare('SELECT * FROM products WHERE slug = ?')
      .bind(c.req.param('slug'))
      .first();
    if (!product) return jsonError(c, 'Product not found', 404);
    return c.json(product);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Blog ─────────────────────────────────────

/** GET /api/blog — published posts, newest first */
app.get('/api/blog', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT * FROM blog_posts WHERE published = 1 ORDER BY published_at DESC',
    ).all();
    return c.json(results);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** GET /api/blog/:slug — single blog post */
app.get('/api/blog/:slug', async (c) => {
  try {
    const post = await c.env.DB.prepare('SELECT * FROM blog_posts WHERE slug = ?')
      .bind(c.req.param('slug'))
      .first();
    if (!post) return jsonError(c, 'Post not found', 404);
    return c.json(post);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Subscribers ──────────────────────────────

/** POST /api/subscribe — add email subscriber */
app.post('/api/subscribe', async (c) => {
  try {
    const { email, phone } = await c.req.json();
    if (!email) return jsonError(c, 'Email is required');

    await c.env.DB.prepare('INSERT INTO subscribers (email, phone) VALUES (?, ?)')
      .bind(email, phone || null)
      .run();

    return c.json({ success: true, message: 'Subscribed successfully' });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) {
      return c.json({ success: true, message: 'Already subscribed' });
    }
    return jsonError(c, err.message, 500);
  }
});

// ── Site Settings ────────────────────────────

/** GET /api/site-settings — all settings as key-value object */
app.get('/api/site-settings', async (c) => {
  try {
    const { results } = await c.env.DB.prepare('SELECT key, value FROM site_settings').all();
    const settings = {};
    for (const row of results) {
      settings[row.key] = row.value;
    }
    return c.json(settings);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Page Sections ────────────────────────────

/** GET /api/pages/:page — visible sections for a page, ordered by position */
app.get('/api/pages/:page', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT * FROM page_sections WHERE page = ? AND visible = 1 ORDER BY position ASC',
    )
      .bind(c.req.param('page'))
      .all();
    return c.json(results);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Analytics Tracking (Public) ──────────────

/** POST /api/track — log a page view for analytics */
app.post('/api/track', async (c) => {
  try {
    const { page, product_slug, referrer } = await c.req.json();
    if (!page) return jsonError(c, 'page is required');

    await c.env.DB.prepare(
      'INSERT INTO page_views (page, product_slug, referrer, viewed_at) VALUES (?, ?, ?, datetime(\'now\'))'
    ).bind(page, product_slug || null, referrer || null).run();

    return c.json({ success: true });
  } catch (err) {
    // Silently succeed even if table doesn't exist — tracking should never break the site
    return c.json({ success: true });
  }
});

// ── Discount Validation (Public) ────────────

/** POST /api/validate-discount — validate a discount code for checkout */
app.post('/api/validate-discount', async (c) => {
  try {
    const { code, order_total } = await c.req.json();
    if (!code) return jsonError(c, 'Discount code is required');
    if (order_total == null || order_total < 0) return jsonError(c, 'Valid order_total is required');

    const result = await validateDiscountCode(c.env.DB, code, order_total);
    if (!result.valid) {
      return c.json({ valid: false, error: result.error }, 400);
    }

    return c.json(result);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Tax Rate Lookup (Public) ────────────────

/** GET /api/tax-rate/:state — get tax rate for a state */
app.get('/api/tax-rate/:state', async (c) => {
  try {
    const state = c.req.param('state').toUpperCase();

    const taxRate = await c.env.DB.prepare(
      'SELECT state, rate, country FROM tax_rates WHERE UPPER(state) = ? AND country = ?'
    ).bind(state, 'US').first();

    if (!taxRate) {
      return c.json({ state, rate: 0, country: 'US', message: 'No tax rate configured for this state' });
    }

    return c.json(taxRate);
  } catch (err) {
    // If tax_rates table doesn't exist, return 0
    return c.json({ state: c.req.param('state').toUpperCase(), rate: 0, country: 'US' });
  }
});

// ═════════════════════════════════════════════
//  CHECKOUT ROUTES
// ═════════════════════════════════════════════

/** POST /api/checkout — create Stripe Checkout Session + pending order */
app.post('/api/checkout', async (c) => {
  try {
    const { items, customer } = await c.req.json();

    if (!items || !items.length) return jsonError(c, 'No items provided');
    if (!customer || !customer.name || !customer.email) {
      return jsonError(c, 'Customer name and email are required');
    }

    // Validate products & stock
    const lineItems = [];
    const orderItems = [];
    let subtotal = 0;

    for (const item of items) {
      const product = await c.env.DB.prepare('SELECT * FROM products WHERE id = ?')
        .bind(item.product_id)
        .first();

      if (!product) return jsonError(c, `Product ${item.product_id} not found`, 404);
      if (product.status === 'draft') return jsonError(c, `Product "${product.name}" is unavailable`);

      // Check inventory
      const inventory = JSON.parse(product.inventory || '{}');
      const available = inventory[item.size] || 0;
      if (available < item.quantity) {
        return jsonError(c, `"${product.name}" (${item.size}) — only ${available} left`);
      }

      const amount = Math.round(product.price * 100); // cents
      subtotal += product.price * item.quantity;

      lineItems.push({
        price_data: {
          currency: 'usd',
          product_data: { name: `${product.name} — ${item.size}` },
          unit_amount: amount,
        },
        quantity: item.quantity,
      });

      orderItems.push({
        product_id: product.id,
        name: product.name,
        size: item.size,
        quantity: item.quantity,
        price: product.price,
      });
    }

    const total = subtotal; // shipping can be added later

    // Generate order number
    const orderNumber = await generateOrderNumber(c.env.DB);

    // Insert pending order
    await c.env.DB.prepare(
      `INSERT INTO orders (order_number, customer_name, customer_email, customer_phone,
        shipping_address, items, subtotal, total, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
    )
      .bind(
        orderNumber,
        customer.name,
        customer.email,
        customer.phone || null,
        JSON.stringify(customer.address || {}),
        JSON.stringify(orderItems),
        subtotal,
        total,
      )
      .run();

    // Fetch the newly created order id
    const newOrder = await c.env.DB.prepare(
      'SELECT id FROM orders WHERE order_number = ?',
    )
      .bind(orderNumber)
      .first();

    // Build Stripe Checkout Session via REST API
    const origin = new URL(c.req.url).origin;

    const params = new URLSearchParams();
    params.append('mode', 'payment');
    params.append('success_url', `${origin}/order-confirmation?order=${orderNumber}`);
    params.append('cancel_url', `${origin}/cart`);
    params.append('client_reference_id', String(newOrder.id));
    params.append('customer_email', customer.email);
    params.append('metadata[order_number]', orderNumber);
    params.append('metadata[order_id]', String(newOrder.id));

    lineItems.forEach((li, i) => {
      params.append(`line_items[${i}][price_data][currency]`, li.price_data.currency);
      params.append(`line_items[${i}][price_data][product_data][name]`, li.price_data.product_data.name);
      params.append(`line_items[${i}][price_data][unit_amount]`, String(li.price_data.unit_amount));
      params.append(`line_items[${i}][quantity]`, String(li.quantity));
    });

    const stripeRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${c.env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    const session = await stripeRes.json();
    if (session.error) {
      return jsonError(c, session.error.message, 502);
    }

    // Store Stripe session id on the order
    await c.env.DB.prepare('UPDATE orders SET stripe_payment_id = ? WHERE id = ?')
      .bind(session.id, newOrder.id)
      .run();

    return c.json({ url: session.url, order_id: newOrder.id });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Stripe Webhook ───────────────────────────

/** POST /api/webhook/stripe — handle Stripe webhook events */
app.post('/api/webhook/stripe', async (c) => {
  try {
    const body = await c.req.text();
    const sig = c.req.header('stripe-signature');

    // Verify webhook signature
    if (c.env.STRIPE_WEBHOOK_SECRET && sig) {
      const verified = await verifyStripeSignature(body, sig, c.env.STRIPE_WEBHOOK_SECRET);
      if (!verified) {
        return jsonError(c, 'Invalid signature', 401);
      }
    }

    const event = JSON.parse(body);

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const orderId = session.metadata?.order_id || session.client_reference_id;

      if (orderId) {
        // Update order status to paid
        await c.env.DB.prepare(
          "UPDATE orders SET status = 'paid', stripe_payment_id = ?, updated_at = datetime('now') WHERE id = ?",
        )
          .bind(session.payment_intent || session.id, orderId)
          .run();

        // Decrement inventory
        const order = await c.env.DB.prepare('SELECT items FROM orders WHERE id = ?')
          .bind(orderId)
          .first();

        if (order) {
          const items = JSON.parse(order.items);
          for (const item of items) {
            const product = await c.env.DB.prepare('SELECT inventory FROM products WHERE id = ?')
              .bind(item.product_id)
              .first();

            if (product) {
              const inventory = JSON.parse(product.inventory || '{}');
              inventory[item.size] = Math.max(0, (inventory[item.size] || 0) - item.quantity);

              // Check if all sizes are sold out
              const allOut = Object.values(inventory).every((v) => v <= 0);

              await c.env.DB.prepare(
                "UPDATE products SET inventory = ?, status = ?, updated_at = datetime('now') WHERE id = ?",
              )
                .bind(
                  JSON.stringify(inventory),
                  allOut ? 'sold_out' : 'active',
                  item.product_id,
                )
                .run();
            }
          }
        }
      }
    }

    return c.json({ received: true });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** Verify Stripe webhook signature (v1 scheme) */
async function verifyStripeSignature(payload, sigHeader, secret) {
  try {
    const parts = {};
    sigHeader.split(',').forEach((kv) => {
      const [k, v] = kv.split('=');
      if (!parts[k]) parts[k] = [];
      parts[k].push(v);
    });

    const timestamp = parts['t']?.[0];
    const signatures = parts['v1'] || [];
    if (!timestamp || !signatures.length) return false;

    // Reject if timestamp is more than 5 minutes old
    const age = Math.floor(Date.now() / 1000) - parseInt(timestamp, 10);
    if (Math.abs(age) > 300) return false;

    const signedPayload = `${timestamp}.${payload}`;
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
    const expected = [...new Uint8Array(mac)]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    return signatures.some((s) => s === expected);
  } catch {
    return false;
  }
}

// ═════════════════════════════════════════════
//  IMAGE SERVING
// ═════════════════════════════════════════════

/** GET /api/images/:key — serve image from R2 with proper headers */
app.get('/api/images/:key', async (c) => {
  try {
    const key = c.req.param('key');
    const object = await c.env.IMAGES.get(key);

    if (!object) return jsonError(c, 'Image not found', 404);

    const headers = new Headers();
    headers.set('Content-Type', object.httpMetadata?.contentType || contentTypeFromKey(key));
    headers.set('Cache-Control', 'public, max-age=31536000, immutable');
    headers.set('ETag', object.httpEtag || '');

    return new Response(object.body, { headers });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ═════════════════════════════════════════════
//  ADMIN ROUTES
// ═════════════════════════════════════════════

// ── Setup & Login ────────────────────────────

/** POST /api/admin/setup — create first admin user (only if none exist) */
app.post('/api/admin/setup', async (c) => {
  try {
    const existing = await c.env.DB.prepare('SELECT COUNT(*) as count FROM admin_users').first();
    if (existing.count > 0) {
      return jsonError(c, 'Admin user already exists. Use login instead.', 403);
    }

    const { username, password, display_name } = await c.req.json();
    if (!username || !password) return jsonError(c, 'Username and password are required');

    const hash = await hashPassword(password);
    await c.env.DB.prepare(
      'INSERT INTO admin_users (username, password_hash, display_name) VALUES (?, ?, ?)',
    )
      .bind(username, hash, display_name || username)
      .run();

    const user = await c.env.DB.prepare('SELECT id, username, display_name FROM admin_users WHERE username = ?')
      .bind(username)
      .first();

    const token = await signJWT({ sub: user.id, username: user.username }, c.env.JWT_SECRET);

    return c.json({ token, user });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** POST /api/admin/login — authenticate admin user */
app.post('/api/admin/login', async (c) => {
  try {
    const { username, password } = await c.req.json();
    if (!username || !password) return jsonError(c, 'Username and password are required');

    const user = await c.env.DB.prepare(
      'SELECT id, username, display_name, password_hash FROM admin_users WHERE username = ?',
    )
      .bind(username)
      .first();

    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return jsonError(c, 'Invalid credentials', 401);
    }

    const token = await signJWT({ sub: user.id, username: user.username }, c.env.JWT_SECRET);

    return c.json({
      token,
      user: { id: user.id, username: user.username, display_name: user.display_name },
    });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Admin Products ───────────────────────────

/** POST /api/admin/products — create a new product */
app.post('/api/admin/products', async (c) => {
  try {
    const data = await c.req.json();
    if (!data.name || data.price == null) return jsonError(c, 'Name and price are required');

    const slug = await generateSlug(c.env.DB, 'products', data.name);

    // Determine next position
    const maxPos = await c.env.DB.prepare('SELECT MAX(position) as max FROM products').first();
    const position = (maxPos?.max || 0) + 1;

    await c.env.DB.prepare(
      `INSERT INTO products (name, slug, description, price, compare_at_price, sizes, inventory,
        images, status, category, position)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        data.name,
        slug,
        data.description || null,
        data.price,
        data.compare_at_price || null,
        JSON.stringify(data.sizes || []),
        JSON.stringify(data.inventory || {}),
        JSON.stringify(data.images || []),
        data.status || 'draft',
        data.category || null,
        position,
      )
      .run();

    const product = await c.env.DB.prepare('SELECT * FROM products WHERE slug = ?')
      .bind(slug)
      .first();

    return c.json(product, 201);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** PUT /api/admin/products/:id — update product fields */
app.put('/api/admin/products/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const data = await c.req.json();

    const product = await c.env.DB.prepare('SELECT * FROM products WHERE id = ?').bind(id).first();
    if (!product) return jsonError(c, 'Product not found', 404);

    // Build dynamic SET clause
    const fields = [
      'name', 'description', 'price', 'compare_at_price', 'status', 'category', 'position',
    ];
    const jsonFields = ['sizes', 'inventory', 'images'];
    const sets = [];
    const values = [];

    for (const f of fields) {
      if (data[f] !== undefined) {
        sets.push(`${f} = ?`);
        values.push(data[f]);
      }
    }
    for (const f of jsonFields) {
      if (data[f] !== undefined) {
        sets.push(`${f} = ?`);
        values.push(JSON.stringify(data[f]));
      }
    }

    // If name changed, regenerate slug
    if (data.name && data.name !== product.name) {
      const slug = await generateSlug(c.env.DB, 'products', data.name);
      sets.push('slug = ?');
      values.push(slug);
    }

    if (sets.length === 0) return jsonError(c, 'No fields to update');

    sets.push("updated_at = datetime('now')");
    values.push(id);

    await c.env.DB.prepare(`UPDATE products SET ${sets.join(', ')} WHERE id = ?`)
      .bind(...values)
      .run();

    const updated = await c.env.DB.prepare('SELECT * FROM products WHERE id = ?').bind(id).first();
    return c.json(updated);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** DELETE /api/admin/products/:id — delete product */
app.delete('/api/admin/products/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const product = await c.env.DB.prepare('SELECT id FROM products WHERE id = ?').bind(id).first();
    if (!product) return jsonError(c, 'Product not found', 404);

    await c.env.DB.prepare('DELETE FROM products WHERE id = ?').bind(id).run();
    return c.json({ success: true });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** PUT /api/admin/products/reorder — update position for each product */
app.put('/api/admin/products/reorder', async (c) => {
  try {
    const { ids } = await c.req.json();
    if (!ids || !Array.isArray(ids)) return jsonError(c, 'ids array is required');

    const stmts = ids.map((id, i) =>
      c.env.DB.prepare('UPDATE products SET position = ? WHERE id = ?').bind(i + 1, id),
    );
    await c.env.DB.batch(stmts);

    return c.json({ success: true });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Admin Orders ─────────────────────────────

/** GET /api/admin/orders/stats — aggregate order statistics */
app.get('/api/admin/orders/stats', async (c) => {
  try {
    const stats = await c.env.DB.prepare(`
      SELECT
        COUNT(*) as total_orders,
        COALESCE(SUM(total), 0) as total_revenue,
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count,
        SUM(CASE WHEN status = 'shipped' THEN 1 ELSE 0 END) as shipped_count
      FROM orders
    `).first();

    return c.json(stats);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** GET /api/admin/orders — all orders, newest first */
app.get('/api/admin/orders', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT * FROM orders ORDER BY created_at DESC',
    ).all();
    return c.json(results);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** GET /api/admin/orders/:id — single order with full details */
app.get('/api/admin/orders/:id', async (c) => {
  try {
    const order = await c.env.DB.prepare('SELECT * FROM orders WHERE id = ?')
      .bind(c.req.param('id'))
      .first();
    if (!order) return jsonError(c, 'Order not found', 404);
    return c.json(order);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** PUT /api/admin/orders/:id — update order status, tracking, carrier, notes */
app.put('/api/admin/orders/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const data = await c.req.json();

    const order = await c.env.DB.prepare('SELECT id FROM orders WHERE id = ?').bind(id).first();
    if (!order) return jsonError(c, 'Order not found', 404);

    const fields = ['status', 'tracking_number', 'carrier', 'notes'];
    const sets = [];
    const values = [];

    for (const f of fields) {
      if (data[f] !== undefined) {
        sets.push(`${f} = ?`);
        values.push(data[f]);
      }
    }

    if (sets.length === 0) return jsonError(c, 'No fields to update');

    sets.push("updated_at = datetime('now')");
    values.push(id);

    await c.env.DB.prepare(`UPDATE orders SET ${sets.join(', ')} WHERE id = ?`)
      .bind(...values)
      .run();

    const updated = await c.env.DB.prepare('SELECT * FROM orders WHERE id = ?').bind(id).first();
    return c.json(updated);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Admin Blog ───────────────────────────────

/** GET /api/admin/blog — all posts including drafts */
app.get('/api/admin/blog', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT * FROM blog_posts ORDER BY created_at DESC',
    ).all();
    return c.json(results);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** POST /api/admin/blog — create blog post */
app.post('/api/admin/blog', async (c) => {
  try {
    const data = await c.req.json();
    if (!data.title) return jsonError(c, 'Title is required');

    const slug = await generateSlug(c.env.DB, 'blog_posts', data.title);
    const publishedAt = data.published ? new Date().toISOString() : null;

    await c.env.DB.prepare(
      `INSERT INTO blog_posts (title, slug, content, excerpt, image_url, published, published_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        data.title,
        slug,
        data.content || null,
        data.excerpt || null,
        data.image_url || null,
        data.published ? 1 : 0,
        publishedAt,
      )
      .run();

    const post = await c.env.DB.prepare('SELECT * FROM blog_posts WHERE slug = ?')
      .bind(slug)
      .first();

    return c.json(post, 201);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** PUT /api/admin/blog/:id — update blog post */
app.put('/api/admin/blog/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const data = await c.req.json();

    const post = await c.env.DB.prepare('SELECT * FROM blog_posts WHERE id = ?').bind(id).first();
    if (!post) return jsonError(c, 'Post not found', 404);

    const fields = ['title', 'content', 'excerpt', 'image_url', 'published', 'published_at'];
    const sets = [];
    const values = [];

    for (const f of fields) {
      if (data[f] !== undefined) {
        sets.push(`${f} = ?`);
        values.push(f === 'published' ? (data[f] ? 1 : 0) : data[f]);
      }
    }

    // If being published for the first time, set published_at
    if (data.published && !post.published) {
      if (!data.published_at) {
        sets.push('published_at = ?');
        values.push(new Date().toISOString());
      }
    }

    // If title changed, regenerate slug
    if (data.title && data.title !== post.title) {
      const slug = await generateSlug(c.env.DB, 'blog_posts', data.title);
      sets.push('slug = ?');
      values.push(slug);
    }

    if (sets.length === 0) return jsonError(c, 'No fields to update');

    sets.push("updated_at = datetime('now')");
    values.push(id);

    await c.env.DB.prepare(`UPDATE blog_posts SET ${sets.join(', ')} WHERE id = ?`)
      .bind(...values)
      .run();

    const updated = await c.env.DB.prepare('SELECT * FROM blog_posts WHERE id = ?').bind(id).first();
    return c.json(updated);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** DELETE /api/admin/blog/:id — delete blog post */
app.delete('/api/admin/blog/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const post = await c.env.DB.prepare('SELECT id FROM blog_posts WHERE id = ?').bind(id).first();
    if (!post) return jsonError(c, 'Post not found', 404);

    await c.env.DB.prepare('DELETE FROM blog_posts WHERE id = ?').bind(id).run();
    return c.json({ success: true });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Admin Subscribers ────────────────────────

/** GET /api/admin/subscribers — all subscribers */
app.get('/api/admin/subscribers', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT * FROM subscribers ORDER BY created_at DESC',
    ).all();
    return c.json(results);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** GET /api/admin/subscribers/export — CSV export */
app.get('/api/admin/subscribers/export', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT email, phone, source, created_at FROM subscribers ORDER BY created_at DESC',
    ).all();

    let csv = 'email,phone,source,subscribed_at\n';
    for (const r of results) {
      csv += `"${r.email}","${r.phone || ''}","${r.source || ''}","${r.created_at}"\n`;
    }

    return new Response(csv, {
      headers: {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="subscribers.csv"',
      },
    });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** DELETE /api/admin/subscribers/:id — remove subscriber */
app.delete('/api/admin/subscribers/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const sub = await c.env.DB.prepare('SELECT id FROM subscribers WHERE id = ?').bind(id).first();
    if (!sub) return jsonError(c, 'Subscriber not found', 404);

    await c.env.DB.prepare('DELETE FROM subscribers WHERE id = ?').bind(id).run();
    return c.json({ success: true });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Admin Image Upload ───────────────────────

/** POST /api/admin/upload — upload file to R2 */
app.post('/api/admin/upload', async (c) => {
  try {
    const formData = await c.req.formData();
    const file = formData.get('file');

    if (!file) return jsonError(c, 'No file provided');

    // Generate a unique filename
    const ext = file.name?.split('.').pop() || 'jpg';
    const key = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;

    await c.env.IMAGES.put(key, file.stream(), {
      httpMetadata: { contentType: file.type || contentTypeFromKey(key) },
    });

    return c.json({ url: `/api/images/${key}`, key });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** DELETE /api/admin/images/:key — delete image from R2 */
app.delete('/api/admin/images/:key', async (c) => {
  try {
    const key = c.req.param('key');
    await c.env.IMAGES.delete(key);
    return c.json({ success: true });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Admin Page Builder ───────────────────────

/** GET /api/admin/pages/:page/sections — all sections (including hidden) */
app.get('/api/admin/pages/:page/sections', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      'SELECT * FROM page_sections WHERE page = ? ORDER BY position ASC',
    )
      .bind(c.req.param('page'))
      .all();
    return c.json(results);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** POST /api/admin/pages/:page/sections — create section */
app.post('/api/admin/pages/:page/sections', async (c) => {
  try {
    const page = c.req.param('page');
    const data = await c.req.json();

    // Determine next position
    const maxPos = await c.env.DB.prepare(
      'SELECT MAX(position) as max FROM page_sections WHERE page = ?',
    )
      .bind(page)
      .first();
    const position = (maxPos?.max || 0) + 1;

    await c.env.DB.prepare(
      `INSERT INTO page_sections (page, section_type, config, position, visible)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind(
        page,
        data.section_type || data.type || 'custom',
        JSON.stringify(data.config || {}),
        position,
        data.visible !== undefined ? (data.visible ? 1 : 0) : 1,
      )
      .run();

    const section = await c.env.DB.prepare(
      'SELECT * FROM page_sections WHERE page = ? AND position = ?',
    )
      .bind(page, position)
      .first();

    return c.json(section, 201);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** PUT /api/admin/pages/:page/sections/reorder — reorder sections */
app.put('/api/admin/pages/:page/sections/reorder', async (c) => {
  try {
    const { ids } = await c.req.json();
    if (!ids || !Array.isArray(ids)) return jsonError(c, 'ids array is required');

    const stmts = ids.map((id, i) =>
      c.env.DB.prepare('UPDATE page_sections SET position = ? WHERE id = ?').bind(i + 1, id),
    );
    await c.env.DB.batch(stmts);

    return c.json({ success: true });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** PUT /api/admin/pages/:page/sections/:id/visibility — toggle visibility */
app.put('/api/admin/pages/:page/sections/:id/visibility', async (c) => {
  try {
    const id = c.req.param('id');

    const section = await c.env.DB.prepare('SELECT visible FROM page_sections WHERE id = ?')
      .bind(id)
      .first();
    if (!section) return jsonError(c, 'Section not found', 404);

    const newVisible = section.visible ? 0 : 1;
    await c.env.DB.prepare('UPDATE page_sections SET visible = ? WHERE id = ?')
      .bind(newVisible, id)
      .run();

    return c.json({ id: Number(id), visible: !!newVisible });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** PUT /api/admin/pages/:page/sections/:id — update section config */
app.put('/api/admin/pages/:page/sections/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const data = await c.req.json();

    const section = await c.env.DB.prepare('SELECT id FROM page_sections WHERE id = ?')
      .bind(id)
      .first();
    if (!section) return jsonError(c, 'Section not found', 404);

    const sets = [];
    const values = [];

    if (data.section_type !== undefined || data.type !== undefined) {
      sets.push('section_type = ?');
      values.push(data.section_type || data.type);
    }
    if (data.config !== undefined) {
      sets.push('config = ?');
      values.push(JSON.stringify(data.config));
    }
    if (data.visible !== undefined) {
      sets.push('visible = ?');
      values.push(data.visible ? 1 : 0);
    }

    if (sets.length === 0) return jsonError(c, 'No fields to update');

    values.push(id);
    await c.env.DB.prepare(`UPDATE page_sections SET ${sets.join(', ')} WHERE id = ?`)
      .bind(...values)
      .run();

    const updated = await c.env.DB.prepare('SELECT * FROM page_sections WHERE id = ?')
      .bind(id)
      .first();
    return c.json(updated);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** DELETE /api/admin/pages/:page/sections/:id — delete section */
app.delete('/api/admin/pages/:page/sections/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const section = await c.env.DB.prepare('SELECT id FROM page_sections WHERE id = ?')
      .bind(id)
      .first();
    if (!section) return jsonError(c, 'Section not found', 404);

    await c.env.DB.prepare('DELETE FROM page_sections WHERE id = ?').bind(id).run();
    return c.json({ success: true });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ── Admin Site Settings ──────────────────────

/** GET /api/admin/settings — all settings */
app.get('/api/admin/settings', async (c) => {
  try {
    const { results } = await c.env.DB.prepare('SELECT key, value FROM site_settings').all();
    const settings = {};
    for (const row of results) {
      settings[row.key] = row.value;
    }
    return c.json(settings);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** PUT /api/admin/settings — upsert multiple settings */
app.put('/api/admin/settings', async (c) => {
  try {
    const data = await c.req.json();
    const stmts = Object.entries(data).map(([key, value]) =>
      c.env.DB.prepare(
        'INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
      ).bind(key, typeof value === 'string' ? value : JSON.stringify(value)),
    );

    if (stmts.length) await c.env.DB.batch(stmts);

    // Return updated settings
    const { results } = await c.env.DB.prepare('SELECT key, value FROM site_settings').all();
    const settings = {};
    for (const row of results) {
      settings[row.key] = row.value;
    }
    return c.json(settings);
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ═════════════════════════════════════════════
//  CAMPAIGN ROUTES
// ═════════════════════════════════════════════

/** Build branded campaign HTML email template */
const LOGO_URL = 'https://mercado-goods.com/cdn/shop/files/Gallo_design_width_22.5_Gallo_Design_Length-4.png?v=1739886113&width=300';

async function buildCampaignHTMLWithConfig(db, template, data) {
  // Load template config from database
  let tc = null;
  try {
    const row = await db.prepare("SELECT value FROM site_settings WHERE key = 'email_template_config'").first();
    if (row) tc = JSON.parse(row.value);
  } catch {}
  return buildCampaignHTML(template, data, tc);
}

function buildCampaignHTML(template, data, tc) {
  // Template config with defaults
  const t = tc || {};
  const bg = t.background_color || '#ffffff';
  const card = t.card_color || '#ffffff';
  const textCol = t.text_color || '#333333';
  const headCol = t.heading_color || '#0a0a0a';
  const accent = t.accent_color || '#cb6305';
  const logoText = t.logo_text || 'MERCADO GOODS';
  const footerText = t.footer_text || 'Mercado Goods — Heritage-Focused Clothing';
  const btnStyle = t.button_style || 'rounded';
  const fontFam = t.font_family || "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif";
  const btnRadius = btnStyle === 'pill' ? '50px' : btnStyle === 'square' ? '0' : '6px';

  const headline = data.headline || 'Mercado Goods';
  const bodyText = data.body_text || '';
  const ctaText = data.cta_text || 'Shop Now';
  const ctaUrl = data.cta_url || 'https://mercado-goods.com/shop.html';
  const imageUrl = data.image_url || '';

  const bodyHtml = bodyText.split('\n').map(line =>
    `<p style="margin:0 0 14px 0;color:${textCol};font-size:16px;line-height:1.7;">${line}</p>`
  ).join('');

  let eventBlock = '';
  if (template === 'event' && (data.event_date || data.event_location)) {
    eventBlock = `<table width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;background:${bg === '#ffffff' ? '#f5f5f5' : '#111111'};border-radius:8px;border:1px solid ${bg === '#ffffff' ? '#e0e0e0' : '#2a2a2a'};">
      <tr><td style="padding:24px;">
      ${data.event_date ? `<p style="margin:0 0 8px;color:${accent};font-size:14px;font-weight:600;letter-spacing:1px;text-transform:uppercase;">&#128197; ${data.event_date}</p>` : ''}
      ${data.event_location ? `<p style="margin:0;color:${headCol};font-size:15px;">&#128205; ${data.event_location}</p>` : ''}
      </td></tr></table>`;
  }

  const headerBg = bg === '#ffffff' ? '#fafafa' : '#111111';
  const borderCol = bg === '#ffffff' ? '#e8e8e8' : '#2a2a2a';
  const footerBg = bg === '#ffffff' ? '#f5f5f5' : '#111111';
  const mutedText = bg === '#ffffff' ? '#999999' : '#666666';

  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:${bg};font-family:${fontFam};">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:${bg};padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background-color:${card};border-radius:8px;overflow:hidden;max-width:100%;${bg === '#ffffff' ? 'border:1px solid #e8e8e8;' : ''}">
        <tr><td style="background:${headerBg};padding:28px 40px;text-align:center;border-bottom:2px solid ${accent};">
          <img src="${LOGO_URL}" alt="Mercado Goods" style="height:40px;width:auto;margin-bottom:12px;display:block;margin-left:auto;margin-right:auto;">
          <h1 style="margin:0;color:${headCol};font-size:18px;font-weight:700;letter-spacing:3px;">${logoText}</h1>
        </td></tr>
        ${imageUrl ? `<tr><td style="padding:0;"><img src="${imageUrl}" alt="" style="width:100%;display:block;max-height:300px;object-fit:cover;"></td></tr>` : ''}
        <tr><td style="padding:40px;">
          <h2 style="margin:0 0 20px;color:${headCol};font-size:28px;font-weight:700;line-height:1.3;">${headline}</h2>
          ${bodyHtml}
          ${eventBlock}
          <table width="100%" cellpadding="0" cellspacing="0" style="margin:28px 0 0;"><tr><td align="center">
            <a href="${ctaUrl}" style="display:inline-block;background:${accent};color:#ffffff;text-decoration:none;padding:16px 40px;border-radius:${btnRadius};font-weight:700;font-size:14px;letter-spacing:2px;text-transform:uppercase;">${ctaText}</a>
          </td></tr></table>
        </td></tr>
        <tr><td style="background:${footerBg};padding:24px 40px;text-align:center;border-top:1px solid ${borderCol};">
          <p style="margin:0 0 8px;color:${mutedText};font-size:12px;">${footerText}</p>
          <p style="margin:0 0 12px;color:${mutedText};font-size:11px;opacity:0.7;">You received this because you subscribed to our list.</p>
          <p style="margin:0;">
            <a href="{{unsubscribeUrl}}" style="color:${mutedText};font-size:11px;text-decoration:underline;">Unsubscribe</a>
            &nbsp;|&nbsp;
            <a href="https://instagram.com/mercadogoods" style="color:${mutedText};font-size:11px;text-decoration:underline;">Instagram</a>
            &nbsp;|&nbsp;
            <a href="https://tiktok.com/@mercadogoods" style="color:${mutedText};font-size:11px;text-decoration:underline;">TikTok</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

/** GET /api/admin/omnisend/campaigns — proxy to Omnisend API, return campaign list with stats */
app.get('/api/admin/omnisend/campaigns', async (c) => {
  try {
    if (!c.env.OMNISEND_API_KEY) {
      return c.json({ campaigns: [], error: 'OMNISEND_API_KEY not configured' });
    }

    const res = await fetch('https://api.omnisend.com/v3/campaigns?limit=50&sort=desc', {
      headers: { 'X-API-KEY': c.env.OMNISEND_API_KEY },
    });

    if (!res.ok) {
      const errText = await res.text();
      return c.json({ campaigns: [], error: `Omnisend API error (${res.status}): ${errText}` });
    }

    const data = await res.json();
    const campaigns = (data.campaigns || []).map(camp => ({
      id: camp.campaignID,
      name: camp.name,
      status: camp.status,
      sent_at: camp.sentAt,
      created_at: camp.createdAt,
      sent_count: camp.stats?.sent || 0,
      open_rate: camp.stats?.openRate || 0,
      click_rate: camp.stats?.clickRate || 0,
      stats: camp.stats || {},
    }));

    return c.json({ campaigns });
  } catch (err) {
    return c.json({ campaigns: [], error: err.message });
  }
});

/** GET /api/admin/omnisend/contacts/count — return total contact count and breakdown */
app.get('/api/admin/omnisend/contacts/count', async (c) => {
  try {
    // First try Omnisend
    if (c.env.OMNISEND_API_KEY) {
      const res = await fetch('https://api.omnisend.com/v3/contacts?limit=1', {
        headers: { 'X-API-KEY': c.env.OMNISEND_API_KEY },
      });

      if (res.ok) {
        const data = await res.json();
        return c.json({
          total: data.totalCount || 0,
          subscribed: data.totalCount || 0,
          unsubscribed: 0,
          non_subscribed: 0,
          source: 'omnisend',
        });
      }
    }

    // Fallback to local subscribers
    const total = await c.env.DB.prepare('SELECT COUNT(*) as count FROM subscribers').first();
    return c.json({
      total: total?.count || 0,
      subscribed: total?.count || 0,
      unsubscribed: 0,
      non_subscribed: 0,
      source: 'local',
    });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

/** POST /api/admin/campaigns/send — create and send a campaign via Omnisend API */
app.post('/api/admin/campaigns/send', async (c) => {
  try {
    const { name, subject, from_name, html_content, sms_message, channel, audience, schedule_at } = await c.req.json();
    if (!name) return jsonError(c, 'Campaign name is required');

    const sendChannel = channel || 'email';

    if ((sendChannel === 'email' || sendChannel === 'both') && !subject) {
      return jsonError(c, 'Subject line is required for email campaigns');
    }
    if ((sendChannel === 'sms' || sendChannel === 'both') && !sms_message) {
      return jsonError(c, 'SMS message is required for SMS campaigns');
    }

    if (!c.env.OMNISEND_API_KEY) {
      return jsonError(c, 'OMNISEND_API_KEY is not configured. Add it in Cloudflare Worker settings.', 500);
    }

    const results = [];

    // Send email campaign via Omnisend
    if (sendChannel === 'email' || sendChannel === 'both') {
      const campaignBody = {
        name: sendChannel === 'both' ? name + ' (Email)' : name,
        subject,
        senderName: from_name || 'Mercado Goods',
        type: 'regular',
        html: html_content || '<p>No content</p>',
      };
      if (schedule_at) campaignBody.scheduledAt = schedule_at;

      const createRes = await fetch('https://api.omnisend.com/v3/campaigns', {
        method: 'POST',
        headers: {
          'X-API-KEY': c.env.OMNISEND_API_KEY,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(campaignBody),
      });

      if (!createRes.ok) {
        const errText = await createRes.text();
        results.push({ channel: 'email', success: false, error: `Omnisend error: ${errText}` });
      } else {
        const campaign = await createRes.json();
        if (!schedule_at && campaign.campaignID) {
          await fetch(`https://api.omnisend.com/v3/campaigns/${campaign.campaignID}/actions/send`, {
            method: 'POST',
            headers: { 'X-API-KEY': c.env.OMNISEND_API_KEY },
          });
        }
        results.push({ channel: 'email', success: true, campaign_id: campaign.campaignID, status: schedule_at ? 'scheduled' : 'sending' });
      }
    }

    // Send SMS campaign via Omnisend
    if (sendChannel === 'sms' || sendChannel === 'both') {
      const smsCampaignBody = {
        name: sendChannel === 'both' ? name + ' (SMS)' : name,
        type: 'sms',
        sms: { message: sms_message },
      };
      if (schedule_at) smsCampaignBody.scheduledAt = schedule_at;

      const smsRes = await fetch('https://api.omnisend.com/v3/campaigns', {
        method: 'POST',
        headers: {
          'X-API-KEY': c.env.OMNISEND_API_KEY,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(smsCampaignBody),
      });

      if (!smsRes.ok) {
        const errText = await smsRes.text();
        results.push({ channel: 'sms', success: false, error: `Omnisend SMS error: ${errText}` });
      } else {
        const smsCampaign = await smsRes.json();
        if (!schedule_at && smsCampaign.campaignID) {
          await fetch(`https://api.omnisend.com/v3/campaigns/${smsCampaign.campaignID}/actions/send`, {
            method: 'POST',
            headers: { 'X-API-KEY': c.env.OMNISEND_API_KEY },
          });
        }
        results.push({ channel: 'sms', success: true, campaign_id: smsCampaign.campaignID, status: schedule_at ? 'scheduled' : 'sending' });
      }
    }

    const allSuccess = results.every(r => r.success);
    const anySuccess = results.some(r => r.success);

    return c.json({
      success: anySuccess,
      results,
      message: allSuccess
        ? (schedule_at ? 'Campaign scheduled!' : 'Campaign sent!')
        : results.map(r => r.error).filter(Boolean).join('; '),
    });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// Legacy Resend fallback removed — Omnisend handles all campaigns

/** POST /api/admin/campaigns/test — send a test email */
app.post('/api/admin/campaigns/test', async (c) => {
  try {
    const { to_email, subject, html_content } = await c.req.json();
    if (!to_email || !html_content) {
      return jsonError(c, 'to_email and html_content are required');
    }

    const result = await sendEmail(
      c.env,
      to_email,
      subject || '[TEST] Campaign Preview',
      html_content
    );

    if (!result.success) {
      return jsonError(c, result.error, 500);
    }

    return c.json({ success: true, sent_to: to_email, email_id: result.email_id });
  } catch (err) {
    return jsonError(c, err.message, 500);
  }
});

// ═════════════════════════════════════════════
//  AI ADMIN ASSISTANT
// ═════════════════════════════════════════════

const AI_SYSTEM_PROMPT = `You are the AI for Mercado Goods (heritage clothing brand by Gerardo Mercado). You have FULL control of the entire website. Never say "I can't" — use your tools.

SITE FILES (in public/): index.html, shop.html, product.html, cart.html, blog.html, post.html, about.html, checkout-success.html, admin.html, builder.html, cart.js. Use read_site_file and edit_site_file to change ANY of them.

EMAIL TEMPLATES: Built by buildCampaignHTML() in worker.js. To change email design, use edit_site_file on worker.js to rewrite that function. The admin Campaigns tab preview also uses buildCampaignPreviewHTML() in admin.html — edit that file too so preview matches. Use customize_email_template for quick color/font changes, or edit the actual code for full control.

BRAND: bg #0a0a0a, text #f5eedd, accent #cb6305, navy #08264b. Fonts: UnifrakturMaguntia, Assistant, Cormorant Garamond.
LOGO URL: https://mercado-goods.com/cdn/shop/files/Gallo_design_width_22.5_Gallo_Design_Length-4.png?v=1739886113&width=300
Always use this logo URL when adding the logo to emails, pages, or anywhere else.

DB TABLES: products, orders, blog_posts, subscribers, admin_users, page_sections, site_settings, discounts, page_views, seo_meta, tax_rates, notifications_log, refunds, inventory_alerts, redirects.

Product sizes: S/M/L/XL/2XL/3XL/One Size. Statuses: active/draft/sold_out.

IMPORTANT RULES:
- For color changes, use update_site_settings (changes primary_color, background_color, text_color). This is INSTANT — the storefront reads these from the API dynamically. Do NOT edit HTML files for color changes.
- For content changes (products, blog, settings, sections), use the database tools. These are INSTANT.
- Only use edit_site_file for structural HTML/CSS changes (layout, new sections, fonts, etc). These require a redeploy to go live.
- Always use tools to make changes. Never tell user to go elsewhere.
- Be concise. Confirm what you did.`;

const AI_TOOLS = [
  {
    name: 'create_product',
    description: 'Create a new product in the store. Returns the created product.',
    input_schema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Product name' },
        description: { type: 'string', description: 'Product description (HTML allowed)' },
        price: { type: 'number', description: 'Price in USD' },
        compare_at_price: { type: 'number', description: 'Original/compare-at price (optional, for showing discounts)' },
        sizes: { type: 'array', items: { type: 'string' }, description: 'Available sizes, e.g. ["S","M","L","XL"]' },
        inventory: { type: 'object', description: 'Inventory per size, e.g. {"S":10,"M":15,"L":10,"XL":5}' },
        images: { type: 'array', items: { type: 'string' }, description: 'Array of image URLs' },
        status: { type: 'string', enum: ['active', 'draft', 'sold_out'], description: 'Product status' },
        category: { type: 'string', description: 'Product category' },
      },
      required: ['name', 'price'],
    },
  },
  {
    name: 'update_product',
    description: 'Update an existing product. Only include fields you want to change.',
    input_schema: {
      type: 'object',
      properties: {
        product_id: { type: 'number', description: 'The product ID to update' },
        name: { type: 'string' },
        description: { type: 'string' },
        price: { type: 'number' },
        compare_at_price: { type: 'number' },
        sizes: { type: 'array', items: { type: 'string' } },
        inventory: { type: 'object' },
        images: { type: 'array', items: { type: 'string' } },
        status: { type: 'string', enum: ['active', 'draft', 'sold_out'] },
        category: { type: 'string' },
      },
      required: ['product_id'],
    },
  },
  {
    name: 'delete_product',
    description: 'Delete a product from the store.',
    input_schema: {
      type: 'object',
      properties: {
        product_id: { type: 'number', description: 'The product ID to delete' },
      },
      required: ['product_id'],
    },
  },
  {
    name: 'list_products',
    description: 'List all products in the store, including drafts and sold out items.',
    input_schema: { type: 'object', properties: {} },
  },
  {
    name: 'upload_image',
    description: 'Upload a base64-encoded image to the site. Returns the URL to use.',
    input_schema: {
      type: 'object',
      properties: {
        base64_data: { type: 'string', description: 'Base64-encoded image data (without data URL prefix)' },
        filename: { type: 'string', description: 'Desired filename with extension, e.g. "jacket-front.jpg"' },
        content_type: { type: 'string', description: 'MIME type, e.g. "image/jpeg"' },
      },
      required: ['base64_data', 'filename'],
    },
  },
  {
    name: 'create_blog_post',
    description: 'Create a new blog post.',
    input_schema: {
      type: 'object',
      properties: {
        title: { type: 'string', description: 'Post title' },
        content: { type: 'string', description: 'Full post content (HTML allowed)' },
        excerpt: { type: 'string', description: 'Short excerpt/summary' },
        published: { type: 'boolean', description: 'Whether to publish immediately (default true)' },
        image_url: { type: 'string', description: 'Featured image URL' },
      },
      required: ['title'],
    },
  },
  {
    name: 'update_blog_post',
    description: 'Update an existing blog post.',
    input_schema: {
      type: 'object',
      properties: {
        post_id: { type: 'number', description: 'The blog post ID to update' },
        title: { type: 'string' },
        content: { type: 'string' },
        excerpt: { type: 'string' },
        published: { type: 'boolean' },
        image_url: { type: 'string' },
      },
      required: ['post_id'],
    },
  },
  {
    name: 'delete_blog_post',
    description: 'Delete a blog post.',
    input_schema: {
      type: 'object',
      properties: {
        post_id: { type: 'number', description: 'The blog post ID to delete' },
      },
      required: ['post_id'],
    },
  },
  {
    name: 'list_blog_posts',
    description: 'List all blog posts including drafts.',
    input_schema: { type: 'object', properties: {} },
  },
  {
    name: 'update_site_settings',
    description: 'Update site-wide settings. Pass key-value pairs. Common keys: site_name, tagline, hero_title, hero_subtitle, hero_image, primary_color, announcement_bar, etc.',
    input_schema: {
      type: 'object',
      properties: {
        settings: { type: 'object', description: 'Key-value pairs of settings to update' },
      },
      required: ['settings'],
    },
  },
  {
    name: 'get_site_settings',
    description: 'Get all current site settings.',
    input_schema: { type: 'object', properties: {} },
  },
  {
    name: 'list_orders',
    description: 'List all orders with details.',
    input_schema: { type: 'object', properties: {} },
  },
  {
    name: 'update_order',
    description: 'Update an order status, tracking number, or carrier.',
    input_schema: {
      type: 'object',
      properties: {
        order_id: { type: 'number', description: 'The order ID to update' },
        status: { type: 'string', enum: ['pending', 'paid', 'shipped', 'delivered', 'cancelled'], description: 'New order status' },
        tracking_number: { type: 'string', description: 'Tracking number' },
        carrier: { type: 'string', description: 'Shipping carrier name' },
        notes: { type: 'string', description: 'Internal notes' },
      },
      required: ['order_id'],
    },
  },
  {
    name: 'list_subscribers',
    description: 'List all email subscribers.',
    input_schema: { type: 'object', properties: {} },
  },
  {
    name: 'update_page_section',
    description: 'Update a page section config (hero, featured products, etc).',
    input_schema: {
      type: 'object',
      properties: {
        section_id: { type: 'number', description: 'The section ID to update' },
        section_type: { type: 'string', description: 'Section type if changing it' },
        config: { type: 'object', description: 'New config object for the section' },
        visible: { type: 'boolean', description: 'Whether the section is visible' },
      },
      required: ['section_id'],
    },
  },
  {
    name: 'create_page_section',
    description: 'Create a new page section.',
    input_schema: {
      type: 'object',
      properties: {
        page: { type: 'string', description: 'Page name, e.g. "home", "shop", "about"' },
        section_type: { type: 'string', description: 'Section type, e.g. "hero", "featured", "text", "custom"' },
        config: { type: 'object', description: 'Section configuration' },
        visible: { type: 'boolean', description: 'Whether visible (default true)' },
      },
      required: ['page', 'section_type'],
    },
  },
  {
    name: 'delete_page_section',
    description: 'Delete a page section.',
    input_schema: {
      type: 'object',
      properties: {
        section_id: { type: 'number', description: 'The section ID to delete' },
      },
      required: ['section_id'],
    },
  },
  {
    name: 'reorder_page_sections',
    description: 'Reorder sections on a page. Provide the page name and an array of section IDs in the desired order.',
    input_schema: {
      type: 'object',
      properties: {
        page: { type: 'string', description: 'Page name, e.g. "home"' },
        section_ids: { type: 'array', items: { type: 'number' }, description: 'Array of section IDs in the desired display order' },
      },
      required: ['page', 'section_ids'],
    },
  },
  {
    name: 'list_page_sections',
    description: 'List all sections on a page with their IDs, types, positions, and visibility. Use this to see what sections exist before reordering or editing them.',
    input_schema: {
      type: 'object',
      properties: {
        page: { type: 'string', description: 'Page name, e.g. "home"' },
      },
      required: ['page'],
    },
  },
  {
    name: 'toggle_section_visibility',
    description: 'Show or hide a page section without deleting it.',
    input_schema: {
      type: 'object',
      properties: {
        section_id: { type: 'number', description: 'The section ID' },
        visible: { type: 'boolean', description: 'true to show, false to hide' },
      },
      required: ['section_id', 'visible'],
    },
  },
  {
    name: 'reorder_products',
    description: 'Reorder products in the shop. Provide product IDs in desired display order.',
    input_schema: {
      type: 'object',
      properties: {
        product_ids: { type: 'array', items: { type: 'number' }, description: 'Array of product IDs in desired order' },
      },
      required: ['product_ids'],
    },
  },
  {
    name: 'edit_site_file',
    description: 'Edit an actual HTML/CSS/JS file in the website repository via GitHub. This allows making code-level changes to any page. The file will be committed to GitHub. A redeploy may be needed for changes to go live.',
    input_schema: {
      type: 'object',
      properties: {
        filename: { type: 'string', description: 'File path relative to public/, e.g. "index.html", "shop.html", "cart.js"' },
        new_content: { type: 'string', description: 'The complete new file content' },
        commit_message: { type: 'string', description: 'Git commit message describing the change' },
      },
      required: ['filename', 'new_content'],
    },
  },
  {
    name: 'read_site_file',
    description: 'Read the current content of a website file from GitHub to see what code is there.',
    input_schema: {
      type: 'object',
      properties: {
        filename: { type: 'string', description: 'File path relative to public/, e.g. "index.html", "shop.html"' },
      },
      required: ['filename'],
    },
  },
  {
    name: 'deploy_site',
    description: 'Note that a deploy is needed. The site auto-deploys from GitHub, but this reminds the owner.',
    input_schema: { type: 'object', properties: {} },
  },

  // ── Discount / Promo Codes ──
  {
    name: 'create_discount',
    description: 'Create a new discount/promo code.',
    input_schema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'The discount code (e.g. SAVE20, FREESHIP)' },
        type: { type: 'string', enum: ['percentage', 'fixed_amount', 'free_shipping', 'bogo'], description: 'Discount type' },
        value: { type: 'number', description: 'Discount value — percentage (e.g. 20 for 20%) or fixed dollar amount' },
        min_order_amount: { type: 'number', description: 'Minimum order total to apply discount (optional)' },
        max_uses: { type: 'number', description: 'Maximum number of times this code can be used (optional, null = unlimited)' },
        product_ids: { type: 'array', items: { type: 'number' }, description: 'Limit discount to specific product IDs (optional)' },
        starts_at: { type: 'string', description: 'Start date/time ISO string (optional)' },
        expires_at: { type: 'string', description: 'Expiration date/time ISO string (optional)' },
      },
      required: ['code', 'type', 'value'],
    },
  },
  {
    name: 'list_discounts',
    description: 'List all discount/promo codes.',
    input_schema: { type: 'object', properties: {} },
  },
  {
    name: 'update_discount',
    description: 'Update an existing discount code.',
    input_schema: {
      type: 'object',
      properties: {
        discount_id: { type: 'number', description: 'The discount ID to update' },
        code: { type: 'string' },
        type: { type: 'string', enum: ['percentage', 'fixed_amount', 'free_shipping', 'bogo'] },
        value: { type: 'number' },
        min_order_amount: { type: 'number' },
        max_uses: { type: 'number' },
        product_ids: { type: 'array', items: { type: 'number' } },
        starts_at: { type: 'string' },
        expires_at: { type: 'string' },
        active: { type: 'boolean', description: 'Enable or disable the discount' },
      },
      required: ['discount_id'],
    },
  },
  {
    name: 'delete_discount',
    description: 'Delete a discount code.',
    input_schema: {
      type: 'object',
      properties: {
        discount_id: { type: 'number', description: 'The discount ID to delete' },
      },
      required: ['discount_id'],
    },
  },
  {
    name: 'validate_discount',
    description: 'Validate a discount code against an order total. Returns discount details if valid.',
    input_schema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'The discount code to validate' },
        order_total: { type: 'number', description: 'The current order total' },
      },
      required: ['code', 'order_total'],
    },
  },

  // ── Stripe Refunds ──
  {
    name: 'refund_order',
    description: 'Process a full or partial refund for an order via Stripe. Updates order record.',
    input_schema: {
      type: 'object',
      properties: {
        order_id: { type: 'number', description: 'The order ID to refund' },
        amount: { type: 'number', description: 'Partial refund amount in USD (optional — omit for full refund)' },
        reason: { type: 'string', description: 'Reason for the refund (optional)' },
      },
      required: ['order_id'],
    },
  },

  // ── Customer Email Notifications ──
  {
    name: 'send_order_confirmation',
    description: 'Send an order confirmation email to the customer with order details.',
    input_schema: {
      type: 'object',
      properties: {
        order_id: { type: 'number', description: 'The order ID to send confirmation for' },
      },
      required: ['order_id'],
    },
  },
  {
    name: 'send_shipping_notification',
    description: 'Send a shipping notification email with tracking info to the customer.',
    input_schema: {
      type: 'object',
      properties: {
        order_id: { type: 'number', description: 'The order ID' },
        tracking_number: { type: 'string', description: 'Tracking number' },
        carrier: { type: 'string', description: 'Shipping carrier (e.g. USPS, UPS, FedEx)' },
      },
      required: ['order_id', 'tracking_number', 'carrier'],
    },
  },
  {
    name: 'send_custom_email',
    description: 'Send a custom email to any email address.',
    input_schema: {
      type: 'object',
      properties: {
        to_email: { type: 'string', description: 'Recipient email address' },
        subject: { type: 'string', description: 'Email subject line' },
        body: { type: 'string', description: 'Email body content (plain text — will be styled into HTML)' },
      },
      required: ['to_email', 'subject', 'body'],
    },
  },

  // ── Analytics ──
  {
    name: 'get_analytics',
    description: 'Get store analytics: revenue, order count, top products, page views, subscriber growth.',
    input_schema: {
      type: 'object',
      properties: {
        period: { type: 'string', enum: ['today', 'week', 'month', 'all'], description: 'Time period for analytics (default: month)' },
      },
    },
  },
  {
    name: 'get_product_analytics',
    description: 'Get analytics for a specific product: views, orders, revenue.',
    input_schema: {
      type: 'object',
      properties: {
        product_slug: { type: 'string', description: 'Product slug to get analytics for' },
      },
      required: ['product_slug'],
    },
  },

  // ── Inventory Management ──
  {
    name: 'set_inventory_alert',
    description: 'Set a low stock alert threshold for a product.',
    input_schema: {
      type: 'object',
      properties: {
        product_id: { type: 'number', description: 'Product ID' },
        threshold: { type: 'number', description: 'Alert when any size stock falls below this number' },
        auto_sold_out: { type: 'boolean', description: 'Automatically set product to sold_out when all sizes hit 0' },
      },
      required: ['product_id', 'threshold'],
    },
  },
  {
    name: 'check_low_stock',
    description: 'Check all products for low stock based on their alert thresholds.',
    input_schema: { type: 'object', properties: {} },
  },
  {
    name: 'bulk_update_inventory',
    description: 'Update inventory counts for multiple products/sizes at once.',
    input_schema: {
      type: 'object',
      properties: {
        updates: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              product_id: { type: 'number' },
              size: { type: 'string' },
              quantity: { type: 'number' },
            },
            required: ['product_id', 'size', 'quantity'],
          },
          description: 'Array of inventory updates [{product_id, size, quantity}]',
        },
      },
      required: ['updates'],
    },
  },

  // ── Tax ──
  {
    name: 'set_tax_rate',
    description: 'Add or update a tax rate for a state.',
    input_schema: {
      type: 'object',
      properties: {
        state: { type: 'string', description: 'Two-letter state code (e.g. CA, TX, NY)' },
        rate: { type: 'number', description: 'Tax rate as a percentage (e.g. 8.25 for 8.25%)' },
        country: { type: 'string', description: 'Country code (default: US)' },
      },
      required: ['state', 'rate'],
    },
  },
  {
    name: 'list_tax_rates',
    description: 'List all configured tax rates.',
    input_schema: { type: 'object', properties: {} },
  },
  {
    name: 'calculate_tax',
    description: 'Calculate tax amount for a given state and subtotal.',
    input_schema: {
      type: 'object',
      properties: {
        state: { type: 'string', description: 'Two-letter state code' },
        subtotal: { type: 'number', description: 'Order subtotal in USD' },
      },
      required: ['state', 'subtotal'],
    },
  },

  // ── SEO ──
  {
    name: 'update_seo',
    description: 'Update SEO meta tags for a page, product, or blog post.',
    input_schema: {
      type: 'object',
      properties: {
        page_type: { type: 'string', enum: ['page', 'product', 'blog'], description: 'Type of page' },
        page_identifier: { type: 'string', description: 'Page slug or identifier (e.g. "home", "shop", product slug, blog slug)' },
        meta_title: { type: 'string', description: 'SEO title tag' },
        meta_description: { type: 'string', description: 'SEO meta description' },
        og_image: { type: 'string', description: 'Open Graph image URL' },
      },
      required: ['page_type', 'page_identifier'],
    },
  },
  {
    name: 'get_seo',
    description: 'Get current SEO meta tags for a page, product, or blog post.',
    input_schema: {
      type: 'object',
      properties: {
        page_type: { type: 'string', enum: ['page', 'product', 'blog'], description: 'Type of page' },
        page_identifier: { type: 'string', description: 'Page slug or identifier' },
      },
      required: ['page_type', 'page_identifier'],
    },
  },

  // ── Redirects ──
  {
    name: 'create_redirect',
    description: 'Create a URL redirect (301 or 302).',
    input_schema: {
      type: 'object',
      properties: {
        from_path: { type: 'string', description: 'Source path (e.g. /old-page)' },
        to_path: { type: 'string', description: 'Destination path or URL (e.g. /new-page)' },
        permanent: { type: 'boolean', description: 'True for 301 permanent redirect, false for 302 temporary (default: true)' },
      },
      required: ['from_path', 'to_path'],
    },
  },
  {
    name: 'list_redirects',
    description: 'List all URL redirects.',
    input_schema: { type: 'object', properties: {} },
  },
  {
    name: 'delete_redirect',
    description: 'Delete a URL redirect.',
    input_schema: {
      type: 'object',
      properties: {
        redirect_id: { type: 'number', description: 'The redirect ID to delete' },
      },
      required: ['redirect_id'],
    },
  },

  // ── Omnisend Integration ──
  {
    name: 'get_omnisend_stats',
    description: 'Get subscriber stats and recent campaign info from Omnisend.',
    input_schema: { type: 'object', properties: {} },
  },
  {
    name: 'send_omnisend_campaign',
    description: 'Information about sending an Omnisend campaign.',
    input_schema: { type: 'object', properties: {} },
  },

  // ── Campaign Management ──
  {
    name: 'create_campaign',
    description: 'Create and send an email campaign to subscribers. Builds a branded HTML email from the provided template and data.',
    input_schema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Campaign name' },
        subject: { type: 'string', description: 'Email subject line' },
        headline: { type: 'string', description: 'Main headline in the email' },
        body_text: { type: 'string', description: 'Body text content of the email' },
        cta_text: { type: 'string', description: 'Call-to-action button text (default: Shop Now)' },
        cta_url: { type: 'string', description: 'Call-to-action button URL' },
        template: { type: 'string', enum: ['new_drop', 'event', 'newsletter'], description: 'Email template type' },
        image_url: { type: 'string', description: 'Hero image URL (optional)' },
        audience: { type: 'string', description: 'Target audience: all, subscribed, or custom (default: all)' },
      },
      required: ['name', 'subject', 'headline', 'body_text'],
    },
  },
  {
    name: 'customize_email_template',
    description: 'Customize the email campaign template design. You can change colors, fonts, layout, logo, footer text, and the overall look and feel. Returns the updated template HTML so you can preview it.',
    input_schema: {
      type: 'object',
      properties: {
        background_color: { type: 'string', description: 'Main background color (default: #0a0a0a)' },
        card_color: { type: 'string', description: 'Email card background color (default: #1a1a1a)' },
        text_color: { type: 'string', description: 'Body text color (default: #c4b99a)' },
        heading_color: { type: 'string', description: 'Heading text color (default: #f5eedd)' },
        accent_color: { type: 'string', description: 'Accent/button color (default: #cb6305)' },
        logo_text: { type: 'string', description: 'Logo text in header (default: MERCADO GOODS)' },
        footer_text: { type: 'string', description: 'Footer text (default: Mercado Goods — Heritage-Focused Clothing)' },
        button_style: { type: 'string', description: 'Button border-radius: rounded, square, pill (default: rounded)' },
        font_family: { type: 'string', description: 'Font family for the email' },
        custom_html: { type: 'string', description: 'If provided, completely replaces the default template with custom HTML. Use {{headline}}, {{body}}, {{cta_text}}, {{cta_url}}, {{image_url}} as placeholders.' },
      },
    },
  },
  {
    name: 'send_custom_html_campaign',
    description: 'Send a campaign with fully custom HTML email content. Use this when the user wants complete control over the email design.',
    input_schema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Campaign name' },
        subject: { type: 'string', description: 'Email subject line' },
        html_content: { type: 'string', description: 'Complete HTML email content' },
        sms_message: { type: 'string', description: 'SMS message text (optional, for SMS campaigns)' },
        channel: { type: 'string', enum: ['email', 'sms', 'both'], description: 'Channel to send on' },
        audience: { type: 'string', description: 'Target audience (default: all)' },
      },
      required: ['name', 'subject', 'html_content'],
    },
  },
  {
    name: 'list_campaigns',
    description: 'List past email campaigns with their stats (sent count, open rate, click rate).',
    input_schema: { type: 'object', properties: {} },
  },
  {
    name: 'get_subscriber_stats',
    description: 'Get subscriber counts by status (total, subscribed, unsubscribed).',
    input_schema: { type: 'object', properties: {} },
  },

  // ── Shipping ──
  {
    name: 'estimate_shipping',
    description: 'Estimate shipping cost based on package weight and destination state.',
    input_schema: {
      type: 'object',
      properties: {
        weight_oz: { type: 'number', description: 'Package weight in ounces' },
        destination_state: { type: 'string', description: 'Two-letter destination state code' },
      },
      required: ['weight_oz', 'destination_state'],
    },
  },
];

// ─────────────────────────────────────────────
// EMAIL HELPER (Resend API)
// ─────────────────────────────────────────────

/** Generate a branded HTML email wrapper */
function buildEmailHTML(title, bodyContent) {
  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0a0a0a;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background-color:#141414;border-radius:8px;overflow:hidden;">
        <tr><td style="background-color:#1a1a1a;padding:30px 40px;text-align:center;border-bottom:2px solid #cb6305;">
          <h1 style="margin:0;color:#f5eedd;font-size:24px;font-weight:700;letter-spacing:2px;">MERCADO GOODS</h1>
        </td></tr>
        <tr><td style="padding:40px;">
          <h2 style="color:#f5eedd;font-size:20px;margin:0 0 20px 0;">${title}</h2>
          <div style="color:#c4b99a;font-size:15px;line-height:1.7;">
            ${bodyContent}
          </div>
        </td></tr>
        <tr><td style="background-color:#1a1a1a;padding:20px 40px;text-align:center;border-top:1px solid #2a2a2a;">
          <p style="margin:0;color:#666;font-size:12px;">Mercado Goods &mdash; Heritage-Focused Clothing</p>
          <p style="margin:5px 0 0 0;color:#555;font-size:11px;">If you have questions, reply to this email.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

/** Send an email via the Resend API */
async function sendEmail(env, to, subject, htmlContent) {
  if (!env.RESEND_API_KEY) {
    return { success: false, error: 'RESEND_API_KEY is not configured. Add it as a secret in your Cloudflare Worker settings.' };
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'Mercado Goods <noreply@mercado-goods.com>',
      to: Array.isArray(to) ? to : [to],
      subject,
      html: htmlContent,
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    return { success: false, error: `Resend API error (${res.status}): ${errText}` };
  }

  const data = await res.json();
  return { success: true, email_id: data.id };
}

// ─────────────────────────────────────────────
// DISCOUNT VALIDATION HELPER
// ─────────────────────────────────────────────

/** Validate a discount code against order details. Returns {valid, discount, discount_amount, error} */
async function validateDiscountCode(db, code, orderTotal) {
  const discount = await db.prepare(
    'SELECT * FROM discounts WHERE UPPER(code) = UPPER(?) AND active = 1'
  ).bind(code).first();

  if (!discount) return { valid: false, error: 'Invalid discount code' };

  const now = new Date().toISOString();
  if (discount.starts_at && now < discount.starts_at) {
    return { valid: false, error: 'This discount code is not yet active' };
  }
  if (discount.expires_at && now > discount.expires_at) {
    return { valid: false, error: 'This discount code has expired' };
  }
  if (discount.max_uses && discount.times_used >= discount.max_uses) {
    return { valid: false, error: 'This discount code has reached its usage limit' };
  }
  if (discount.min_order_amount && orderTotal < discount.min_order_amount) {
    return { valid: false, error: `Minimum order of $${discount.min_order_amount.toFixed(2)} required for this code` };
  }

  let discountAmount = 0;
  switch (discount.type) {
    case 'percentage':
      discountAmount = Math.round((orderTotal * discount.value / 100) * 100) / 100;
      break;
    case 'fixed_amount':
      discountAmount = Math.min(discount.value, orderTotal);
      break;
    case 'free_shipping':
      discountAmount = 0; // Shipping discount handled at checkout
      break;
    case 'bogo':
      discountAmount = 0; // BOGO logic handled at item level
      break;
  }

  return {
    valid: true,
    discount: {
      id: discount.id,
      code: discount.code,
      type: discount.type,
      value: discount.value,
      min_order_amount: discount.min_order_amount,
      free_shipping: discount.type === 'free_shipping',
    },
    discount_amount: discountAmount,
    new_total: Math.max(0, orderTotal - discountAmount),
  };
}

/** Execute a single AI tool call against the database/R2/GitHub */
async function executeAITool(toolName, toolInput, env) {
  const db = env.DB;
  const images = env.IMAGES;

  try {
    switch (toolName) {
      // ── Products ──
      case 'create_product': {
        const data = toolInput;
        const slug = await generateSlug(db, 'products', data.name);
        const maxPos = await db.prepare('SELECT MAX(position) as max FROM products').first();
        const position = (maxPos?.max || 0) + 1;

        await db.prepare(
          `INSERT INTO products (name, slug, description, price, compare_at_price, sizes, inventory,
            images, status, category, position)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          data.name,
          slug,
          data.description || null,
          data.price,
          data.compare_at_price || null,
          JSON.stringify(data.sizes || []),
          JSON.stringify(data.inventory || {}),
          JSON.stringify(data.images || []),
          data.status || 'active',
          data.category || null,
          position,
        ).run();

        const product = await db.prepare('SELECT * FROM products WHERE slug = ?').bind(slug).first();
        return { success: true, product };
      }

      case 'update_product': {
        const { product_id, ...data } = toolInput;
        const product = await db.prepare('SELECT * FROM products WHERE id = ?').bind(product_id).first();
        if (!product) return { success: false, error: 'Product not found' };

        const fields = ['name', 'description', 'price', 'compare_at_price', 'status', 'category', 'position'];
        const jsonFields = ['sizes', 'inventory', 'images'];
        const sets = [];
        const values = [];

        for (const f of fields) {
          if (data[f] !== undefined) { sets.push(`${f} = ?`); values.push(data[f]); }
        }
        for (const f of jsonFields) {
          if (data[f] !== undefined) { sets.push(`${f} = ?`); values.push(JSON.stringify(data[f])); }
        }
        if (data.name && data.name !== product.name) {
          const slug = await generateSlug(db, 'products', data.name);
          sets.push('slug = ?');
          values.push(slug);
        }

        if (sets.length === 0) return { success: false, error: 'No fields to update' };

        sets.push("updated_at = datetime('now')");
        values.push(product_id);

        await db.prepare(`UPDATE products SET ${sets.join(', ')} WHERE id = ?`).bind(...values).run();
        const updated = await db.prepare('SELECT * FROM products WHERE id = ?').bind(product_id).first();
        return { success: true, product: updated };
      }

      case 'delete_product': {
        const product = await db.prepare('SELECT name FROM products WHERE id = ?').bind(toolInput.product_id).first();
        if (!product) return { success: false, error: 'Product not found' };
        await db.prepare('DELETE FROM products WHERE id = ?').bind(toolInput.product_id).run();
        return { success: true, deleted_product: product.name };
      }

      case 'list_products': {
        const { results } = await db.prepare('SELECT * FROM products ORDER BY position ASC, id ASC').all();
        return { success: true, products: results, count: results.length };
      }

      // ── Images ──
      case 'upload_image': {
        const { base64_data, filename, content_type } = toolInput;
        const ext = filename.split('.').pop() || 'jpg';
        const key = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;

        // Decode base64
        const binaryStr = atob(base64_data);
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
          bytes[i] = binaryStr.charCodeAt(i);
        }

        await images.put(key, bytes.buffer, {
          httpMetadata: { contentType: content_type || contentTypeFromKey(key) },
        });

        const url = `/api/images/${key}`;
        return { success: true, url, key };
      }

      // ── Blog ──
      case 'create_blog_post': {
        const data = toolInput;
        const slug = await generateSlug(db, 'blog_posts', data.title);
        const published = data.published !== false;
        const publishedAt = published ? new Date().toISOString() : null;

        await db.prepare(
          `INSERT INTO blog_posts (title, slug, content, excerpt, image_url, published, published_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          data.title,
          slug,
          data.content || null,
          data.excerpt || null,
          data.image_url || null,
          published ? 1 : 0,
          publishedAt,
        ).run();

        const post = await db.prepare('SELECT * FROM blog_posts WHERE slug = ?').bind(slug).first();
        return { success: true, post };
      }

      case 'update_blog_post': {
        const { post_id, ...data } = toolInput;
        const post = await db.prepare('SELECT * FROM blog_posts WHERE id = ?').bind(post_id).first();
        if (!post) return { success: false, error: 'Blog post not found' };

        const fields = ['title', 'content', 'excerpt', 'image_url'];
        const sets = [];
        const values = [];

        for (const f of fields) {
          if (data[f] !== undefined) { sets.push(`${f} = ?`); values.push(data[f]); }
        }
        if (data.published !== undefined) {
          sets.push('published = ?');
          values.push(data.published ? 1 : 0);
          if (data.published && !post.published) {
            sets.push('published_at = ?');
            values.push(new Date().toISOString());
          }
        }
        if (data.title && data.title !== post.title) {
          const slug = await generateSlug(db, 'blog_posts', data.title);
          sets.push('slug = ?');
          values.push(slug);
        }

        if (sets.length === 0) return { success: false, error: 'No fields to update' };

        sets.push("updated_at = datetime('now')");
        values.push(post_id);

        await db.prepare(`UPDATE blog_posts SET ${sets.join(', ')} WHERE id = ?`).bind(...values).run();
        const updated = await db.prepare('SELECT * FROM blog_posts WHERE id = ?').bind(post_id).first();
        return { success: true, post: updated };
      }

      case 'delete_blog_post': {
        const post = await db.prepare('SELECT title FROM blog_posts WHERE id = ?').bind(toolInput.post_id).first();
        if (!post) return { success: false, error: 'Blog post not found' };
        await db.prepare('DELETE FROM blog_posts WHERE id = ?').bind(toolInput.post_id).run();
        return { success: true, deleted_post: post.title };
      }

      case 'list_blog_posts': {
        const { results } = await db.prepare('SELECT * FROM blog_posts ORDER BY created_at DESC').all();
        return { success: true, posts: results, count: results.length };
      }

      // ── Site Settings ──
      case 'update_site_settings': {
        const settings = toolInput.settings;
        const stmts = Object.entries(settings).map(([key, value]) =>
          db.prepare(
            'INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
          ).bind(key, typeof value === 'string' ? value : JSON.stringify(value))
        );
        if (stmts.length) await db.batch(stmts);

        const { results } = await db.prepare('SELECT key, value FROM site_settings').all();
        const allSettings = {};
        for (const row of results) allSettings[row.key] = row.value;
        return { success: true, settings: allSettings };
      }

      case 'get_site_settings': {
        const { results } = await db.prepare('SELECT key, value FROM site_settings').all();
        const allSettings = {};
        for (const row of results) allSettings[row.key] = row.value;
        return { success: true, settings: allSettings };
      }

      // ── Orders ──
      case 'list_orders': {
        const { results } = await db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all();
        return { success: true, orders: results, count: results.length };
      }

      case 'update_order': {
        const { order_id, ...data } = toolInput;
        const order = await db.prepare('SELECT id FROM orders WHERE id = ?').bind(order_id).first();
        if (!order) return { success: false, error: 'Order not found' };

        const fields = ['status', 'tracking_number', 'carrier', 'notes'];
        const sets = [];
        const values = [];
        for (const f of fields) {
          if (data[f] !== undefined) { sets.push(`${f} = ?`); values.push(data[f]); }
        }

        if (sets.length === 0) return { success: false, error: 'No fields to update' };

        sets.push("updated_at = datetime('now')");
        values.push(order_id);

        await db.prepare(`UPDATE orders SET ${sets.join(', ')} WHERE id = ?`).bind(...values).run();
        const updated = await db.prepare('SELECT * FROM orders WHERE id = ?').bind(order_id).first();
        return { success: true, order: updated };
      }

      // ── Subscribers ──
      case 'list_subscribers': {
        const { results } = await db.prepare('SELECT * FROM subscribers ORDER BY created_at DESC').all();
        return { success: true, subscribers: results, count: results.length };
      }

      // ── Page Sections ──
      case 'update_page_section': {
        const { section_id, ...data } = toolInput;
        const section = await db.prepare('SELECT id FROM page_sections WHERE id = ?').bind(section_id).first();
        if (!section) return { success: false, error: 'Section not found' };

        const sets = [];
        const values = [];
        if (data.section_type !== undefined) { sets.push('section_type = ?'); values.push(data.section_type); }
        if (data.config !== undefined) { sets.push('config = ?'); values.push(JSON.stringify(data.config)); }
        if (data.visible !== undefined) { sets.push('visible = ?'); values.push(data.visible ? 1 : 0); }

        if (sets.length === 0) return { success: false, error: 'No fields to update' };

        values.push(section_id);
        await db.prepare(`UPDATE page_sections SET ${sets.join(', ')} WHERE id = ?`).bind(...values).run();
        const updated = await db.prepare('SELECT * FROM page_sections WHERE id = ?').bind(section_id).first();
        return { success: true, section: updated };
      }

      case 'create_page_section': {
        const data = toolInput;
        const maxPos = await db.prepare('SELECT MAX(position) as max FROM page_sections WHERE page = ?').bind(data.page).first();
        const position = (maxPos?.max || 0) + 1;

        await db.prepare(
          `INSERT INTO page_sections (page, section_type, config, position, visible) VALUES (?, ?, ?, ?, ?)`
        ).bind(
          data.page,
          data.section_type,
          JSON.stringify(data.config || {}),
          position,
          data.visible !== false ? 1 : 0,
        ).run();

        const section = await db.prepare('SELECT * FROM page_sections WHERE page = ? AND position = ?').bind(data.page, position).first();
        return { success: true, section };
      }

      case 'delete_page_section': {
        const section = await db.prepare('SELECT id, section_type FROM page_sections WHERE id = ?').bind(toolInput.section_id).first();
        if (!section) return { success: false, error: 'Section not found' };
        await db.prepare('DELETE FROM page_sections WHERE id = ?').bind(toolInput.section_id).run();
        return { success: true, deleted_section_type: section.section_type };
      }

      case 'reorder_page_sections': {
        const { page, section_ids } = toolInput;
        for (let i = 0; i < section_ids.length; i++) {
          await db.prepare('UPDATE page_sections SET position = ?, updated_at = datetime(\'now\') WHERE id = ? AND page = ?')
            .bind(i, section_ids[i], page).run();
        }
        return { success: true, new_order: section_ids };
      }

      case 'list_page_sections': {
        const { results } = await db.prepare('SELECT id, page, section_type, position, visible, config FROM page_sections WHERE page = ? ORDER BY position ASC')
          .bind(toolInput.page).all();
        return { success: true, sections: results };
      }

      case 'toggle_section_visibility': {
        const vis = toolInput.visible ? 1 : 0;
        await db.prepare('UPDATE page_sections SET visible = ?, updated_at = datetime(\'now\') WHERE id = ?')
          .bind(vis, toolInput.section_id).run();
        return { success: true, section_id: toolInput.section_id, visible: toolInput.visible };
      }

      case 'reorder_products': {
        const { product_ids } = toolInput;
        for (let i = 0; i < product_ids.length; i++) {
          await db.prepare('UPDATE products SET position = ?, updated_at = datetime(\'now\') WHERE id = ?')
            .bind(i, product_ids[i]).run();
        }
        return { success: true, new_order: product_ids };
      }

      // ── GitHub File Editing ──
      case 'edit_site_file': {
        const { filename, new_content, commit_message } = toolInput;
        const ghToken = env.GITHUB_TOKEN;
        if (!ghToken) return { success: false, error: 'GITHUB_TOKEN not configured' };

        const isRootFile = filename === 'worker.js' || filename === 'wrangler.toml' || filename === 'package.json';
        const filePath = isRootFile ? filename : `public/${filename}`;
        const apiUrl = `https://api.github.com/repos/zachxmiller/mercado-goods-redesign/contents/${filePath}`;

        // GET current file to get its SHA
        const getRes = await fetch(apiUrl, {
          headers: {
            'Authorization': `Bearer ${ghToken}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'MercadoGoods-Worker',
          },
        });

        let sha = null;
        if (getRes.ok) {
          const fileData = await getRes.json();
          sha = fileData.sha;
        }

        // PUT new content
        const putBody = {
          message: commit_message || `Update ${filename} via AI assistant`,
          content: btoa(unescape(encodeURIComponent(new_content))),
        };
        if (sha) putBody.sha = sha;

        const putRes = await fetch(apiUrl, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${ghToken}`,
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
            'User-Agent': 'MercadoGoods-Worker',
          },
          body: JSON.stringify(putBody),
        });

        if (!putRes.ok) {
          const errData = await putRes.text();
          return { success: false, error: `GitHub API error: ${putRes.status} — ${errData}` };
        }

        const result = await putRes.json();
        return {
          success: true,
          message: `File "${filename}" updated and committed to GitHub.`,
          commit_sha: result.commit?.sha,
          note: 'A redeploy may be needed for changes to go live. If auto-deploy from GitHub is set up, it will happen automatically.',
        };
      }

      case 'read_site_file': {
        const { filename } = toolInput;
        const ghToken = env.GITHUB_TOKEN;
        if (!ghToken) return { success: false, error: 'GITHUB_TOKEN not configured' };

        // Files like worker.js, wrangler.toml are at repo root; HTML/CSS/JS pages are in public/
        const isRootFile = filename === 'worker.js' || filename === 'wrangler.toml' || filename === 'package.json';
        const filePath = isRootFile ? filename : `public/${filename}`;
        const apiUrl = `https://api.github.com/repos/zachxmiller/mercado-goods-redesign/contents/${filePath}`;
        const res = await fetch(apiUrl, {
          headers: {
            'Authorization': `Bearer ${ghToken}`,
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'MercadoGoods-Worker',
          },
        });

        if (!res.ok) return { success: false, error: `File not found: ${filename}` };

        const fileData = await res.json();
        const content = decodeURIComponent(escape(atob(fileData.content.replace(/\n/g, ''))));
        return { success: true, filename, content, sha: fileData.sha };
      }

      case 'deploy_site': {
        return {
          success: true,
          message: 'Deploy noted. If auto-deploy from GitHub is configured, changes will go live automatically. Otherwise, redeploy manually via the Cloudflare dashboard or wrangler CLI.',
        };
      }

      // ── Discount / Promo Codes ──
      case 'create_discount': {
        const data = toolInput;
        await db.prepare(
          `INSERT INTO discounts (code, type, value, min_order_amount, max_uses, product_ids, starts_at, expires_at, active, times_used)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0)`
        ).bind(
          data.code.toUpperCase(),
          data.type,
          data.value,
          data.min_order_amount || null,
          data.max_uses || null,
          data.product_ids ? JSON.stringify(data.product_ids) : null,
          data.starts_at || null,
          data.expires_at || null,
        ).run();

        const discount = await db.prepare('SELECT * FROM discounts WHERE UPPER(code) = ?')
          .bind(data.code.toUpperCase()).first();
        return { success: true, discount };
      }

      case 'list_discounts': {
        const { results } = await db.prepare('SELECT * FROM discounts ORDER BY created_at DESC').all();
        return { success: true, discounts: results, count: results.length };
      }

      case 'update_discount': {
        const { discount_id, ...data } = toolInput;
        const disc = await db.prepare('SELECT * FROM discounts WHERE id = ?').bind(discount_id).first();
        if (!disc) return { success: false, error: 'Discount not found' };

        const sets = [];
        const values = [];

        if (data.code !== undefined) { sets.push('code = ?'); values.push(data.code.toUpperCase()); }
        if (data.type !== undefined) { sets.push('type = ?'); values.push(data.type); }
        if (data.value !== undefined) { sets.push('value = ?'); values.push(data.value); }
        if (data.min_order_amount !== undefined) { sets.push('min_order_amount = ?'); values.push(data.min_order_amount); }
        if (data.max_uses !== undefined) { sets.push('max_uses = ?'); values.push(data.max_uses); }
        if (data.product_ids !== undefined) { sets.push('product_ids = ?'); values.push(JSON.stringify(data.product_ids)); }
        if (data.starts_at !== undefined) { sets.push('starts_at = ?'); values.push(data.starts_at); }
        if (data.expires_at !== undefined) { sets.push('expires_at = ?'); values.push(data.expires_at); }
        if (data.active !== undefined) { sets.push('active = ?'); values.push(data.active ? 1 : 0); }

        if (sets.length === 0) return { success: false, error: 'No fields to update' };

        sets.push("updated_at = datetime('now')");
        values.push(discount_id);

        await db.prepare(`UPDATE discounts SET ${sets.join(', ')} WHERE id = ?`).bind(...values).run();
        const updated = await db.prepare('SELECT * FROM discounts WHERE id = ?').bind(discount_id).first();
        return { success: true, discount: updated };
      }

      case 'delete_discount': {
        const disc = await db.prepare('SELECT code FROM discounts WHERE id = ?').bind(toolInput.discount_id).first();
        if (!disc) return { success: false, error: 'Discount not found' };
        await db.prepare('DELETE FROM discounts WHERE id = ?').bind(toolInput.discount_id).run();
        return { success: true, deleted_code: disc.code };
      }

      case 'validate_discount': {
        const result = await validateDiscountCode(db, toolInput.code, toolInput.order_total);
        return { success: result.valid, ...result };
      }

      // ── Stripe Refunds ──
      case 'refund_order': {
        if (!env.STRIPE_SECRET_KEY) {
          return { success: false, error: 'STRIPE_SECRET_KEY is not configured. Add it as a secret in your Cloudflare Worker settings.' };
        }

        const order = await db.prepare('SELECT * FROM orders WHERE id = ?').bind(toolInput.order_id).first();
        if (!order) return { success: false, error: 'Order not found' };
        if (!order.stripe_payment_id) return { success: false, error: 'No Stripe payment ID found on this order. Cannot process refund.' };

        const refundAmountCents = toolInput.amount
          ? Math.round(toolInput.amount * 100)
          : Math.round(order.total * 100);

        const params = new URLSearchParams();
        params.append('payment_intent', order.stripe_payment_id);
        params.append('amount', String(refundAmountCents));
        if (toolInput.reason) {
          params.append('reason', 'requested_by_customer');
          params.append('metadata[reason_detail]', toolInput.reason);
        }

        const stripeRes = await fetch('https://api.stripe.com/v1/refunds', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: params.toString(),
        });

        const refundData = await stripeRes.json();
        if (refundData.error) {
          return { success: false, error: `Stripe refund failed: ${refundData.error.message}` };
        }

        // Update order record
        const refundAmount = refundAmountCents / 100;
        await db.prepare(
          "UPDATE orders SET refunded = 1, refund_amount = ?, status = 'refunded', notes = COALESCE(notes, '') || ?, updated_at = datetime('now') WHERE id = ?"
        ).bind(
          refundAmount,
          `\n[Refund] $${refundAmount.toFixed(2)} refunded on ${new Date().toISOString().split('T')[0]}${toolInput.reason ? ' — ' + toolInput.reason : ''}`,
          toolInput.order_id,
        ).run();

        return {
          success: true,
          refund_id: refundData.id,
          amount_refunded: refundAmount,
          order_number: order.order_number,
          message: `Refund of $${refundAmount.toFixed(2)} processed for order ${order.order_number}`,
        };
      }

      // ── Customer Email Notifications ──
      case 'send_order_confirmation': {
        const order = await db.prepare('SELECT * FROM orders WHERE id = ?').bind(toolInput.order_id).first();
        if (!order) return { success: false, error: 'Order not found' };

        const items = JSON.parse(order.items || '[]');
        const itemRows = items.map(item =>
          `<tr>
            <td style="padding:8px 0;color:#f5eedd;border-bottom:1px solid #2a2a2a;">${item.name} — ${item.size}</td>
            <td style="padding:8px 0;color:#cb6305;border-bottom:1px solid #2a2a2a;text-align:right;">$${item.price.toFixed(2)} x ${item.quantity}</td>
          </tr>`
        ).join('');

        const emailBody = `
          <p style="color:#f5eedd;">Hi ${order.customer_name},</p>
          <p>Thank you for your order! Here's your confirmation:</p>
          <div style="background-color:#1a1a1a;border-radius:6px;padding:20px;margin:20px 0;">
            <p style="color:#cb6305;font-size:18px;font-weight:600;margin:0 0 5px 0;">Order ${order.order_number}</p>
            <p style="color:#888;margin:0 0 15px 0;">Placed on ${new Date(order.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
            <table width="100%" cellpadding="0" cellspacing="0">
              ${itemRows}
              <tr>
                <td style="padding:12px 0 0 0;color:#f5eedd;font-weight:600;">Total</td>
                <td style="padding:12px 0 0 0;color:#cb6305;font-weight:600;text-align:right;font-size:18px;">$${order.total.toFixed(2)}</td>
              </tr>
            </table>
          </div>
          <p>We'll send you another email when your order ships.</p>
          <p style="color:#888;margin-top:20px;">— The Mercado Goods Team</p>
        `;

        const html = buildEmailHTML('Order Confirmation', emailBody);
        const result = await sendEmail(env, order.customer_email, `Order Confirmed — ${order.order_number}`, html);
        return { ...result, order_number: order.order_number, sent_to: order.customer_email };
      }

      case 'send_shipping_notification': {
        const order = await db.prepare('SELECT * FROM orders WHERE id = ?').bind(toolInput.order_id).first();
        if (!order) return { success: false, error: 'Order not found' };

        const carrierUrls = {
          'USPS': 'https://tools.usps.com/go/TrackConfirmAction?tLabels=',
          'UPS': 'https://www.ups.com/track?tracknum=',
          'FedEx': 'https://www.fedex.com/fedextrack/?trknbr=',
          'DHL': 'https://www.dhl.com/us-en/home/tracking/tracking-global-forwarding.html?submit=1&tracking-id=',
        };
        const trackingUrl = (carrierUrls[toolInput.carrier] || '') + toolInput.tracking_number;

        const emailBody = `
          <p style="color:#f5eedd;">Hi ${order.customer_name},</p>
          <p>Great news — your order is on its way!</p>
          <div style="background-color:#1a1a1a;border-radius:6px;padding:20px;margin:20px 0;">
            <p style="color:#cb6305;font-size:18px;font-weight:600;margin:0 0 15px 0;">Order ${order.order_number}</p>
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding:5px 0;color:#888;">Carrier</td>
                <td style="padding:5px 0;color:#f5eedd;text-align:right;">${toolInput.carrier}</td>
              </tr>
              <tr>
                <td style="padding:5px 0;color:#888;">Tracking Number</td>
                <td style="padding:5px 0;color:#f5eedd;text-align:right;">${toolInput.tracking_number}</td>
              </tr>
            </table>
            ${trackingUrl ? `<div style="text-align:center;margin-top:20px;">
              <a href="${trackingUrl}" style="display:inline-block;background-color:#cb6305;color:#f5eedd;text-decoration:none;padding:12px 30px;border-radius:4px;font-weight:600;">Track Your Package</a>
            </div>` : ''}
          </div>
          <p style="color:#888;margin-top:20px;">— The Mercado Goods Team</p>
        `;

        // Update order with tracking info
        await db.prepare(
          "UPDATE orders SET tracking_number = ?, carrier = ?, status = 'shipped', updated_at = datetime('now') WHERE id = ?"
        ).bind(toolInput.tracking_number, toolInput.carrier, toolInput.order_id).run();

        const html = buildEmailHTML('Your Order Has Shipped!', emailBody);
        const result = await sendEmail(env, order.customer_email, `Your Order Has Shipped — ${order.order_number}`, html);
        return { ...result, order_number: order.order_number, sent_to: order.customer_email };
      }

      case 'send_custom_email': {
        const bodyHtml = toolInput.body
          .split('\n')
          .map(line => `<p style="margin:0 0 10px 0;">${line}</p>`)
          .join('');

        const html = buildEmailHTML(toolInput.subject, bodyHtml);
        const result = await sendEmail(env, toolInput.to_email, toolInput.subject, html);
        return { ...result, sent_to: toolInput.to_email };
      }

      // ── Analytics ──
      case 'get_analytics': {
        const period = toolInput.period || 'month';
        let dateFilter = '';

        switch (period) {
          case 'today':
            dateFilter = "AND created_at >= datetime('now', 'start of day')";
            break;
          case 'week':
            dateFilter = "AND created_at >= datetime('now', '-7 days')";
            break;
          case 'month':
            dateFilter = "AND created_at >= datetime('now', '-30 days')";
            break;
          case 'all':
            dateFilter = '';
            break;
        }

        // Revenue & orders
        const orderStats = await db.prepare(`
          SELECT
            COUNT(*) as order_count,
            COALESCE(SUM(total), 0) as total_revenue,
            COALESCE(AVG(total), 0) as avg_order_value
          FROM orders
          WHERE status IN ('paid', 'shipped', 'delivered') ${dateFilter}
        `).first();

        // Top products by revenue
        const { results: allOrders } = await db.prepare(`
          SELECT items FROM orders WHERE status IN ('paid', 'shipped', 'delivered') ${dateFilter}
        `).all();

        const productRevenue = {};
        for (const o of allOrders) {
          const items = JSON.parse(o.items || '[]');
          for (const item of items) {
            const key = item.name;
            if (!productRevenue[key]) productRevenue[key] = { name: key, revenue: 0, units_sold: 0 };
            productRevenue[key].revenue += item.price * item.quantity;
            productRevenue[key].units_sold += item.quantity;
          }
        }
        const topProducts = Object.values(productRevenue)
          .sort((a, b) => b.revenue - a.revenue)
          .slice(0, 5);

        // Page views
        let pageViewCount = 0;
        try {
          const pvResult = await db.prepare(`
            SELECT COUNT(*) as count FROM page_views WHERE 1=1 ${dateFilter.replace('created_at', 'viewed_at')}
          `).first();
          pageViewCount = pvResult?.count || 0;
        } catch { /* table may not exist yet */ }

        // Subscriber growth
        let subscriberGrowth = 0;
        try {
          const subResult = await db.prepare(`
            SELECT COUNT(*) as count FROM subscribers WHERE 1=1 ${dateFilter}
          `).first();
          subscriberGrowth = subResult?.count || 0;
        } catch { /* table may not exist */ }

        const totalSubscribers = await db.prepare('SELECT COUNT(*) as count FROM subscribers').first();

        return {
          success: true,
          period,
          total_revenue: Math.round(orderStats.total_revenue * 100) / 100,
          order_count: orderStats.order_count,
          avg_order_value: Math.round(orderStats.avg_order_value * 100) / 100,
          top_products: topProducts,
          page_views: pageViewCount,
          subscriber_growth: subscriberGrowth,
          total_subscribers: totalSubscribers?.count || 0,
        };
      }

      case 'get_product_analytics': {
        const product = await db.prepare('SELECT * FROM products WHERE slug = ?')
          .bind(toolInput.product_slug).first();
        if (!product) return { success: false, error: 'Product not found' };

        // Page views for this product
        let views = 0;
        try {
          const pvResult = await db.prepare(
            'SELECT COUNT(*) as count FROM page_views WHERE product_slug = ?'
          ).bind(toolInput.product_slug).first();
          views = pvResult?.count || 0;
        } catch { /* table may not exist */ }

        // Orders containing this product
        const { results: allOrders } = await db.prepare(
          "SELECT items, total FROM orders WHERE status IN ('paid', 'shipped', 'delivered')"
        ).all();

        let orderCount = 0;
        let revenue = 0;
        let unitsSold = 0;

        for (const o of allOrders) {
          const items = JSON.parse(o.items || '[]');
          for (const item of items) {
            if (item.product_id === product.id) {
              orderCount++;
              revenue += item.price * item.quantity;
              unitsSold += item.quantity;
            }
          }
        }

        return {
          success: true,
          product: product.name,
          slug: product.slug,
          views,
          orders: orderCount,
          units_sold: unitsSold,
          revenue: Math.round(revenue * 100) / 100,
        };
      }

      // ── Inventory Management ──
      case 'set_inventory_alert': {
        const product = await db.prepare('SELECT id, name FROM products WHERE id = ?')
          .bind(toolInput.product_id).first();
        if (!product) return { success: false, error: 'Product not found' };

        await db.prepare(
          `INSERT INTO inventory_alerts (product_id, threshold, auto_sold_out)
           VALUES (?, ?, ?)
           ON CONFLICT(product_id) DO UPDATE SET threshold = excluded.threshold, auto_sold_out = excluded.auto_sold_out, updated_at = datetime('now')`
        ).bind(
          toolInput.product_id,
          toolInput.threshold,
          toolInput.auto_sold_out ? 1 : 0,
        ).run();

        return {
          success: true,
          message: `Inventory alert set for "${product.name}": alert when stock falls below ${toolInput.threshold}`,
          auto_sold_out: !!toolInput.auto_sold_out,
        };
      }

      case 'check_low_stock': {
        const { results: products } = await db.prepare('SELECT * FROM products ORDER BY name ASC').all();
        let alerts;
        try {
          const alertResults = await db.prepare('SELECT * FROM inventory_alerts').all();
          alerts = alertResults.results;
        } catch {
          alerts = [];
        }

        const alertMap = {};
        for (const a of alerts) alertMap[a.product_id] = a;

        const lowStockItems = [];
        for (const product of products) {
          const inventory = JSON.parse(product.inventory || '{}');
          const alert = alertMap[product.id];
          const threshold = alert?.threshold || 5; // default threshold of 5

          for (const [size, qty] of Object.entries(inventory)) {
            if (qty <= threshold) {
              lowStockItems.push({
                product_id: product.id,
                product_name: product.name,
                size,
                quantity: qty,
                threshold,
                is_zero: qty === 0,
              });
            }
          }
        }

        return {
          success: true,
          low_stock_items: lowStockItems,
          count: lowStockItems.length,
          message: lowStockItems.length === 0
            ? 'All products are well-stocked!'
            : `${lowStockItems.length} size(s) across products are at or below their alert threshold.`,
        };
      }

      case 'bulk_update_inventory': {
        const results = [];
        for (const update of toolInput.updates) {
          const product = await db.prepare('SELECT * FROM products WHERE id = ?')
            .bind(update.product_id).first();
          if (!product) {
            results.push({ product_id: update.product_id, success: false, error: 'Product not found' });
            continue;
          }

          const inventory = JSON.parse(product.inventory || '{}');
          inventory[update.size] = update.quantity;

          // Check if all sizes are sold out
          const allOut = Object.values(inventory).every(v => v <= 0);

          // Check if there's an auto_sold_out alert
          let autoSoldOut = false;
          try {
            const alert = await db.prepare('SELECT auto_sold_out FROM inventory_alerts WHERE product_id = ?')
              .bind(update.product_id).first();
            autoSoldOut = alert?.auto_sold_out === 1;
          } catch { /* table may not exist */ }

          const newStatus = (allOut && autoSoldOut) ? 'sold_out' : product.status;

          await db.prepare(
            "UPDATE products SET inventory = ?, status = ?, updated_at = datetime('now') WHERE id = ?"
          ).bind(JSON.stringify(inventory), newStatus, update.product_id).run();

          results.push({
            product_id: update.product_id,
            product_name: product.name,
            size: update.size,
            new_quantity: update.quantity,
            success: true,
          });
        }

        return { success: true, updates: results, count: results.length };
      }

      // ── Tax ──
      case 'set_tax_rate': {
        const country = toolInput.country || 'US';
        await db.prepare(
          `INSERT INTO tax_rates (state, rate, country)
           VALUES (?, ?, ?)
           ON CONFLICT(state, country) DO UPDATE SET rate = excluded.rate, updated_at = datetime('now')`
        ).bind(toolInput.state.toUpperCase(), toolInput.rate, country).run();

        return {
          success: true,
          message: `Tax rate for ${toolInput.state.toUpperCase()} (${country}) set to ${toolInput.rate}%`,
        };
      }

      case 'list_tax_rates': {
        const { results } = await db.prepare('SELECT * FROM tax_rates ORDER BY country, state ASC').all();
        return { success: true, tax_rates: results, count: results.length };
      }

      case 'calculate_tax': {
        const taxRate = await db.prepare(
          'SELECT rate FROM tax_rates WHERE UPPER(state) = UPPER(?) AND country = ?'
        ).bind(toolInput.state, 'US').first();

        if (!taxRate) {
          return {
            success: true,
            state: toolInput.state.toUpperCase(),
            rate: 0,
            tax_amount: 0,
            total_with_tax: toolInput.subtotal,
            message: `No tax rate configured for ${toolInput.state.toUpperCase()}. Tax is $0.00.`,
          };
        }

        const taxAmount = Math.round(toolInput.subtotal * taxRate.rate / 100 * 100) / 100;
        return {
          success: true,
          state: toolInput.state.toUpperCase(),
          rate: taxRate.rate,
          tax_amount: taxAmount,
          total_with_tax: Math.round((toolInput.subtotal + taxAmount) * 100) / 100,
        };
      }

      // ── SEO ──
      case 'update_seo': {
        const { page_type, page_identifier, meta_title, meta_description, og_image } = toolInput;
        const seoKey = `${page_type}:${page_identifier}`;

        const sets = [];
        const values = [];

        if (meta_title !== undefined) { sets.push('meta_title'); values.push(meta_title); }
        if (meta_description !== undefined) { sets.push('meta_description'); values.push(meta_description); }
        if (og_image !== undefined) { sets.push('og_image'); values.push(og_image); }

        await db.prepare(
          `INSERT INTO seo_meta (page_type, page_identifier, meta_title, meta_description, og_image)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(page_type, page_identifier) DO UPDATE SET
             meta_title = COALESCE(excluded.meta_title, seo_meta.meta_title),
             meta_description = COALESCE(excluded.meta_description, seo_meta.meta_description),
             og_image = COALESCE(excluded.og_image, seo_meta.og_image),
             updated_at = datetime('now')`
        ).bind(
          page_type,
          page_identifier,
          meta_title || null,
          meta_description || null,
          og_image || null,
        ).run();

        const updated = await db.prepare(
          'SELECT * FROM seo_meta WHERE page_type = ? AND page_identifier = ?'
        ).bind(page_type, page_identifier).first();

        return { success: true, seo: updated };
      }

      case 'get_seo': {
        const seo = await db.prepare(
          'SELECT * FROM seo_meta WHERE page_type = ? AND page_identifier = ?'
        ).bind(toolInput.page_type, toolInput.page_identifier).first();

        if (!seo) {
          return {
            success: true,
            seo: null,
            message: `No SEO meta tags configured for ${toolInput.page_type}:${toolInput.page_identifier}`,
          };
        }

        return { success: true, seo };
      }

      // ── Redirects ──
      case 'create_redirect': {
        const permanent = toolInput.permanent !== false; // default true
        await db.prepare(
          'INSERT INTO redirects (from_path, to_path, permanent) VALUES (?, ?, ?)'
        ).bind(toolInput.from_path, toolInput.to_path, permanent ? 1 : 0).run();

        const redirect = await db.prepare(
          'SELECT * FROM redirects WHERE from_path = ? ORDER BY id DESC LIMIT 1'
        ).bind(toolInput.from_path).first();

        return {
          success: true,
          redirect,
          message: `${permanent ? '301 Permanent' : '302 Temporary'} redirect created: ${toolInput.from_path} → ${toolInput.to_path}`,
        };
      }

      case 'list_redirects': {
        const { results } = await db.prepare('SELECT * FROM redirects ORDER BY created_at DESC').all();
        return { success: true, redirects: results, count: results.length };
      }

      case 'delete_redirect': {
        const redirect = await db.prepare('SELECT * FROM redirects WHERE id = ?').bind(toolInput.redirect_id).first();
        if (!redirect) return { success: false, error: 'Redirect not found' };
        await db.prepare('DELETE FROM redirects WHERE id = ?').bind(toolInput.redirect_id).run();
        return { success: true, deleted: `${redirect.from_path} → ${redirect.to_path}` };
      }

      // ── Omnisend Integration ──
      case 'get_omnisend_stats': {
        if (!env.OMNISEND_API_KEY) {
          return { success: false, error: 'OMNISEND_API_KEY is not configured. Add it as a secret in your Cloudflare Worker settings.' };
        }

        try {
          const contactsRes = await fetch('https://api.omnisend.com/v3/contacts?limit=1', {
            headers: { 'X-API-KEY': env.OMNISEND_API_KEY },
          });

          if (!contactsRes.ok) {
            const errText = await contactsRes.text();
            return { success: false, error: `Omnisend API error (${contactsRes.status}): ${errText}` };
          }

          const contactsData = await contactsRes.json();

          // Try to get campaigns
          let campaigns = [];
          try {
            const campaignsRes = await fetch('https://api.omnisend.com/v3/campaigns?limit=5&sort=desc', {
              headers: { 'X-API-KEY': env.OMNISEND_API_KEY },
            });
            if (campaignsRes.ok) {
              const campaignsData = await campaignsRes.json();
              campaigns = (campaignsData.campaigns || []).map(c => ({
                name: c.name,
                status: c.status,
                sent_at: c.sentAt,
                stats: c.stats,
              }));
            }
          } catch { /* campaigns endpoint may vary */ }

          return {
            success: true,
            total_contacts: contactsData.totalCount || 0,
            recent_campaigns: campaigns,
            dashboard_url: 'https://app.omnisend.com',
          };
        } catch (err) {
          return { success: false, error: `Failed to connect to Omnisend: ${err.message}` };
        }
      }

      case 'send_omnisend_campaign': {
        return {
          success: true,
          message: 'Campaign creation is best done directly in the Omnisend dashboard where you have full control over templates, segmentation, and scheduling.',
          link: 'https://app.omnisend.com/campaigns',
          instructions: 'Go to app.omnisend.com → Campaigns → Create Campaign to design and send your campaign.',
        };
      }

      // ── Campaign Management ──
      case 'create_campaign': {
        const data = toolInput;
        const template = data.template || 'new_drop';
        const htmlContent = await buildCampaignHTMLWithConfig(db, template, {
          headline: data.headline,
          body_text: data.body_text,
          cta_text: data.cta_text || 'Shop Now',
          cta_url: data.cta_url || 'https://mercado-goods.com/shop.html',
          image_url: data.image_url || '',
          event_date: data.event_date || '',
          event_location: data.event_location || '',
        });

        // Try Omnisend first
        if (env.OMNISEND_API_KEY) {
          try {
            const createRes = await fetch('https://api.omnisend.com/v3/campaigns', {
              method: 'POST',
              headers: {
                'X-API-KEY': env.OMNISEND_API_KEY,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                name: data.name,
                subject: data.subject,
                senderName: 'Mercado Goods',
                type: 'regular',
                html: htmlContent,
              }),
            });

            if (createRes.ok) {
              const campaign = await createRes.json();
              // Send immediately
              if (campaign.campaignID) {
                await fetch(`https://api.omnisend.com/v3/campaigns/${campaign.campaignID}/actions/send`, {
                  method: 'POST',
                  headers: { 'X-API-KEY': env.OMNISEND_API_KEY },
                });
              }
              return {
                success: true,
                campaign_id: campaign.campaignID,
                message: `Campaign "${data.name}" created and sent via Omnisend`,
              };
            }
          } catch { /* fall through to Resend */ }
        }

        // Fallback to Resend
        if (env.RESEND_API_KEY) {
          const { results: subscribers } = await db.prepare('SELECT email FROM subscribers').all();
          if (subscribers.length > 0) {
            const emails = subscribers.map(s => s.email).slice(0, 50);
            const result = await sendEmail(env, emails, data.subject, htmlContent);
            return {
              success: true,
              sent_to: emails.length,
              message: `Campaign "${data.name}" sent to ${emails.length} subscribers via email`,
              ...result,
            };
          }
          return { success: false, error: 'No subscribers to send to' };
        }

        return { success: false, error: 'OMNISEND_API_KEY is not configured' };
      }

      case 'customize_email_template': {
        const settings = toolInput;
        // Store template customizations in site_settings
        const templateConfig = {
          background_color: settings.background_color || '#0a0a0a',
          card_color: settings.card_color || '#1a1a1a',
          text_color: settings.text_color || '#c4b99a',
          heading_color: settings.heading_color || '#f5eedd',
          accent_color: settings.accent_color || '#cb6305',
          logo_text: settings.logo_text || 'MERCADO GOODS',
          footer_text: settings.footer_text || 'Mercado Goods — Heritage-Focused Clothing',
          button_style: settings.button_style || 'rounded',
          font_family: settings.font_family || "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
          custom_html: settings.custom_html || null,
        };

        await db.prepare(
          `INSERT INTO site_settings (key, value, updated_at) VALUES ('email_template_config', ?, datetime('now'))
           ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`
        ).bind(JSON.stringify(templateConfig)).run();

        return {
          success: true,
          message: 'Email template customized. Changes will apply to the next campaign you send.',
          config: templateConfig,
        };
      }

      case 'send_custom_html_campaign': {
        const data = toolInput;
        if (!env.OMNISEND_API_KEY) return { success: false, error: 'OMNISEND_API_KEY not configured' };

        const results = [];
        const channel = data.channel || 'email';

        if (channel === 'email' || channel === 'both') {
          try {
            const createRes = await fetch('https://api.omnisend.com/v3/campaigns', {
              method: 'POST',
              headers: { 'X-API-KEY': env.OMNISEND_API_KEY, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                name: data.name,
                subject: data.subject,
                senderName: 'Mercado Goods',
                type: 'regular',
                html: data.html_content,
              }),
            });
            if (createRes.ok) {
              const campaign = await createRes.json();
              if (campaign.campaignID) {
                await fetch(`https://api.omnisend.com/v3/campaigns/${campaign.campaignID}/actions/send`, {
                  method: 'POST',
                  headers: { 'X-API-KEY': env.OMNISEND_API_KEY },
                });
              }
              results.push({ channel: 'email', success: true, campaign_id: campaign.campaignID });
            } else {
              const errText = await createRes.text();
              results.push({ channel: 'email', success: false, error: errText });
            }
          } catch (err) {
            results.push({ channel: 'email', success: false, error: err.message });
          }
        }

        if ((channel === 'sms' || channel === 'both') && data.sms_message) {
          try {
            const smsRes = await fetch('https://api.omnisend.com/v3/campaigns', {
              method: 'POST',
              headers: { 'X-API-KEY': env.OMNISEND_API_KEY, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                name: data.name + ' (SMS)',
                type: 'sms',
                sms: { message: data.sms_message },
              }),
            });
            if (smsRes.ok) {
              const smsCampaign = await smsRes.json();
              if (smsCampaign.campaignID) {
                await fetch(`https://api.omnisend.com/v3/campaigns/${smsCampaign.campaignID}/actions/send`, {
                  method: 'POST',
                  headers: { 'X-API-KEY': env.OMNISEND_API_KEY },
                });
              }
              results.push({ channel: 'sms', success: true, campaign_id: smsCampaign.campaignID });
            } else {
              const errText = await smsRes.text();
              results.push({ channel: 'sms', success: false, error: errText });
            }
          } catch (err) {
            results.push({ channel: 'sms', success: false, error: err.message });
          }
        }

        return {
          success: results.some(r => r.success),
          results,
          message: `Campaign "${data.name}" processed`,
        };
      }

      case 'list_campaigns': {
        if (env.OMNISEND_API_KEY) {
          try {
            const res = await fetch('https://api.omnisend.com/v3/campaigns?limit=20&sort=desc', {
              headers: { 'X-API-KEY': env.OMNISEND_API_KEY },
            });
            if (res.ok) {
              const data = await res.json();
              const campaigns = (data.campaigns || []).map(c => ({
                name: c.name,
                status: c.status,
                sent_at: c.sentAt,
                sent_count: c.stats?.sent || 0,
                open_rate: c.stats?.openRate || 0,
                click_rate: c.stats?.clickRate || 0,
              }));
              return { success: true, campaigns, count: campaigns.length };
            }
          } catch { /* fall through */ }
        }
        return { success: true, campaigns: [], count: 0, message: 'No campaigns found. Configure OMNISEND_API_KEY to see past campaigns.' };
      }

      case 'get_subscriber_stats': {
        // Try Omnisend first
        if (env.OMNISEND_API_KEY) {
          try {
            const res = await fetch('https://api.omnisend.com/v3/contacts?limit=1', {
              headers: { 'X-API-KEY': env.OMNISEND_API_KEY },
            });
            if (res.ok) {
              const data = await res.json();
              return {
                success: true,
                total: data.totalCount || 0,
                source: 'omnisend',
              };
            }
          } catch { /* fall through */ }
        }

        // Local fallback
        const total = await db.prepare('SELECT COUNT(*) as count FROM subscribers').first();
        return {
          success: true,
          total: total?.count || 0,
          subscribed: total?.count || 0,
          source: 'local',
        };
      }

      // ── Shipping ──
      case 'estimate_shipping': {
        const weightOz = toolInput.weight_oz;
        const weightLbs = weightOz / 16;

        let rate, service;
        if (weightLbs < 1) {
          rate = 5.99;
          service = 'USPS First-Class Package';
        } else if (weightLbs <= 3) {
          rate = 8.99;
          service = 'USPS Priority Mail';
        } else if (weightLbs <= 5) {
          rate = 12.99;
          service = 'USPS Priority Mail';
        } else {
          rate = 12.99 + Math.ceil((weightLbs - 5) / 2) * 3.00;
          service = 'USPS Priority Mail (estimated)';
        }

        return {
          success: true,
          weight_oz: weightOz,
          weight_lbs: Math.round(weightLbs * 100) / 100,
          destination_state: toolInput.destination_state.toUpperCase(),
          estimated_rate: rate,
          service,
          note: 'For actual shipping labels with the cheapest USPS/UPS rates, use pirateship.com — it\'s free and typically offers the best rates. Here are the order details you can copy into PirateShip.',
          pirateship_url: 'https://www.pirateship.com',
        };
      }

      default:
        return { success: false, error: `Unknown tool: ${toolName}` };
    }
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/** POST /api/admin/ai/chat — AI assistant chat endpoint */
app.post('/api/admin/ai/chat', async (c) => {
  try {
    const apiKey = c.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      return c.json({ error: 'ANTHROPIC_API_KEY not configured' }, 500);
    }

    const { message, images, history } = await c.req.json();
    if (!message && (!images || images.length === 0)) {
      return jsonError(c, 'Message or images required');
    }

    // Build user content (text + optional images)
    const userContent = [];

    // Add images as vision content blocks
    if (images && images.length > 0) {
      for (const img of images) {
        // img is a data URL like "data:image/jpeg;base64,/9j/4AAQ..."
        const match = img.match(/^data:(image\/[^;]+);base64,(.+)$/);
        if (match) {
          userContent.push({
            type: 'image',
            source: {
              type: 'base64',
              media_type: match[1],
              data: match[2],
            },
          });
        }
      }
    }

    if (message) {
      userContent.push({ type: 'text', text: message });
    }

    // Build messages array with optional history
    const messages = [];
    if (history && Array.isArray(history)) {
      for (const msg of history) {
        messages.push(msg);
      }
    }
    messages.push({ role: 'user', content: userContent });

    // Call Claude API
    let claudeMessages = [...messages];
    const allActions = [];
    let finalText = '';
    let iterations = 0;
    const MAX_ITERATIONS = 10;

    while (iterations < MAX_ITERATIONS) {
      iterations++;

      const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 4096,
          system: AI_SYSTEM_PROMPT,
          tools: AI_TOOLS,
          messages: claudeMessages,
        }),
      });

      if (!claudeRes.ok) {
        const errText = await claudeRes.text();
        return c.json({ error: `Claude API error: ${claudeRes.status}`, details: errText }, 502);
      }

      const claudeData = await claudeRes.json();

      // Check if Claude wants to use tools
      const toolUseBlocks = claudeData.content.filter((b) => b.type === 'tool_use');
      const textBlocks = claudeData.content.filter((b) => b.type === 'text');

      if (textBlocks.length > 0) {
        finalText = textBlocks.map((b) => b.text).join('\n');
      }

      // If no tool calls, we're done
      if (toolUseBlocks.length === 0 || claudeData.stop_reason !== 'tool_use') {
        break;
      }

      // Execute tool calls and collect results
      const toolResults = [];
      for (const toolBlock of toolUseBlocks) {
        const result = await executeAITool(toolBlock.name, toolBlock.input, c.env);

        allActions.push({
          tool: toolBlock.name,
          input: toolBlock.input,
          result,
        });

        toolResults.push({
          type: 'tool_result',
          tool_use_id: toolBlock.id,
          content: JSON.stringify(result),
        });
      }

      // Add assistant's response and tool results to messages for next iteration
      claudeMessages.push({ role: 'assistant', content: claudeData.content });
      claudeMessages.push({ role: 'user', content: toolResults });
    }

    // Build conversation history entry for the frontend to store
    // Only include the assistant's final content blocks (not tool-use internals)
    return c.json({
      response: finalText,
      actions: allActions,
    });
  } catch (err) {
    return c.json({ error: err.message }, 500);
  }
});

// ═════════════════════════════════════════════
//  CATCH-ALL — fall through to static assets
// ═════════════════════════════════════════════

/** Any non-API route is served by Cloudflare's asset binding */
app.all('*', async (c) => {
  return c.env.ASSETS.fetch(c.req.raw);
});

// ─────────────────────────────────────────────
// EXPORT
// ─────────────────────────────────────────────
export default app;
