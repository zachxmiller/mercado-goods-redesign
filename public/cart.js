// ============================================================
// Mercado Goods — Shared Cart System
// ============================================================

const CART_KEY = 'mercado_cart';

function getCart() {
  try {
    return JSON.parse(localStorage.getItem(CART_KEY)) || [];
  } catch {
    return [];
  }
}

function saveCart(cart) {
  localStorage.setItem(CART_KEY, JSON.stringify(cart));
  updateCartBadge();
}

function addToCart(productId, slug, name, size, quantity, price, image) {
  const cart = getCart();
  const existing = cart.find(item => item.product_id === productId && item.size === size);
  if (existing) {
    existing.quantity += quantity;
  } else {
    cart.push({ product_id: productId, slug, name, size, quantity, price, image });
  }
  saveCart(cart);
}

function removeFromCart(productId, size) {
  let cart = getCart();
  cart = cart.filter(item => !(item.product_id === productId && item.size === size));
  saveCart(cart);
}

function updateQuantity(productId, size, quantity) {
  const cart = getCart();
  const item = cart.find(item => item.product_id === productId && item.size === size);
  if (item) {
    item.quantity = Math.max(1, quantity);
  }
  saveCart(cart);
}

function getCartCount() {
  return getCart().reduce((sum, item) => sum + item.quantity, 0);
}

function getCartTotal() {
  return getCart().reduce((sum, item) => sum + (item.price * item.quantity), 0);
}

function clearCart() {
  localStorage.removeItem(CART_KEY);
  updateCartBadge();
}

function updateCartBadge() {
  const badge = document.getElementById('cartBadge');
  if (badge) {
    const count = getCartCount();
    badge.textContent = count;
    badge.style.display = count > 0 ? 'flex' : 'none';
  }
}

// Update badge on page load
document.addEventListener('DOMContentLoaded', updateCartBadge);
