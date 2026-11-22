/* Shared front-end behaviour. No inline event handlers anywhere in the templates,
   so the Content-Security-Policy never needs to allow them. */
(function () {
  "use strict";

  // ---- CSRF: attach the token to every same-origin non-GET fetch() -------------------
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const nativeFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    init = init || {};
    const method = (init.method || (input instanceof Request ? input.method : "GET")).toUpperCase();
    const url = new URL(input instanceof Request ? input.url : input, location.href);
    if (method !== "GET" && method !== "HEAD" && url.origin === location.origin) {
      const headers = new Headers(init.headers || (input instanceof Request ? input.headers : {}));
      headers.set("X-CSRFToken", csrf);
      init.headers = headers;
    }
    return nativeFetch(input, init);
  };

  // ---- Cart (stored in localStorage; the SERVER re-prices everything at checkout) ----
  const CART_KEY = "mall_cart";
  const readCart = () => {
    try { const c = JSON.parse(localStorage.getItem(CART_KEY) || "[]"); return Array.isArray(c) ? c : []; }
    catch { return []; }
  };
  const writeCart = (c) => localStorage.setItem(CART_KEY, JSON.stringify(c));
  window.MallCart = { read: readCart, write: writeCart, KEY: CART_KEY };

  function addToCart(item, btn) {
    if (!item || !Number.isInteger(item.id)) return;
    const cart = readCart();
    const found = cart.find((i) => i.id === item.id);
    if (found) found.qty = Math.min(20, (found.qty || 1) + 1);
    else cart.push({ id: item.id, name: String(item.name || ""), price: Number(item.price) || 0,
                     image: typeof item.image === "string" ? item.image : null, qty: 1 });
    writeCart(cart);
    if (btn) {
      const original = btn.textContent;
      btn.textContent = "✓ Added";
      btn.classList.add("bg-emerald-600");
      setTimeout(() => { btn.textContent = original; btn.classList.remove("bg-emerald-600"); }, 1200);
    }
  }

  async function toggleWishlist(id, btn) {
    const res = await fetch(`/wishlist/toggle/${encodeURIComponent(id)}`, { method: "POST" });
    if (res.status === 401 || res.redirected) { location.href = "/login"; return; }
    if (!res.ok) return;
    const data = await res.json();
    btn.textContent = data.saved ? "❤️" : "🤍";
  }

  function selectRole(role) {
    document.getElementById("reg-form")?.classList.remove("hidden");
    const input = document.getElementById("role-input");
    if (input) input.value = role;
    const merchant = document.getElementById("merchant-fields");
    const title = document.getElementById("form-title");
    if (role === "merchant") { merchant?.classList.remove("hidden"); if (title) title.textContent = "Merchant Application"; }
    else { merchant?.classList.add("hidden"); if (title) title.textContent = "Create Buyer Account"; }
  }

  // ---- Delegated click handlers (data-* attributes) ----------------------------------
  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-add-to-cart],[data-wishlist],[data-dialog-open],[data-dialog-close],[data-select-role],[data-hide],[data-edit-product]");
    if (!t) return;
    if (t.dataset.addToCart) {
      try { addToCart(JSON.parse(t.dataset.addToCart), t); } catch { /* ignore malformed data */ }
    } else if (t.dataset.wishlist) {
      toggleWishlist(t.dataset.wishlist, t);
    } else if (t.dataset.dialogOpen) {
      document.getElementById(t.dataset.dialogOpen)?.showModal();
    } else if ("dialogClose" in t.dataset) {
      t.closest("dialog")?.close();
    } else if (t.dataset.selectRole) {
      selectRole(t.dataset.selectRole);
    } else if (t.dataset.hide) {
      document.getElementById(t.dataset.hide)?.classList.add("hidden");
    } else if (t.dataset.editProduct) {
      try { window.openEditProduct?.(JSON.parse(t.dataset.editProduct)); } catch { /* ignore */ }
    }
  });

  // ---- Admin: ask for a rejection reason before submitting ---------------------------
  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (form.matches("[data-confirm]") && !confirm(form.dataset.confirm)) { e.preventDefault(); return; }
    if (form.matches("[data-prompt-reason]")) {
      const reason = prompt("Reason for rejecting this application:");
      if (!reason || reason.trim().length < 5) { e.preventDefault(); return; }
      form.reason.value = reason.trim();
    }
  });
})();
