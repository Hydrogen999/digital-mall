/* Cart page. Items live in localStorage but are rendered with textContent only,
   and the server ignores the stored names/prices - it re-prices from the database. */
(function () {
  "use strict";
  const { read, write, KEY } = window.MallCart;
  const fmt = (n) => "₦" + Number(n).toLocaleString("en-NG", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const $ = (id) => document.getElementById(id);

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function render() {
    const cart = read().filter((i) => Number.isInteger(i.id) && i.qty > 0);
    write(cart);
    $("cart-container").classList.toggle("hidden", cart.length === 0);
    $("empty-cart").classList.toggle("hidden", cart.length !== 0);
    const list = $("cart-items");
    list.replaceChildren();
    let total = 0;

    cart.forEach((item) => {
      total += (Number(item.price) || 0) * item.qty;
      const row = el("div", "flex items-center gap-4 bg-white border border-slate-200 rounded-2xl p-4");
      const imgBox = el("div", "w-16 h-16 rounded-lg bg-slate-100 overflow-hidden shrink-0");
      if (typeof item.image === "string" && item.image.startsWith("https://")) {
        const img = el("img", "w-full h-full object-cover");
        img.src = item.image; img.alt = ""; img.referrerPolicy = "no-referrer";
        imgBox.appendChild(img);
      }
      const info = el("div", "flex-1 min-w-0");
      info.append(el("div", "font-semibold truncate", item.name), el("div", "text-sm text-amber-600 font-bold", fmt(item.price)));

      const qty = el("div", "flex items-center gap-2");
      const mk = (label, delta) => {
        const b = el("button", "w-8 h-8 rounded-lg border border-slate-200 hover:bg-slate-50 font-bold", label);
        b.type = "button"; b.setAttribute("aria-label", delta > 0 ? "Increase quantity" : "Decrease quantity");
        b.addEventListener("click", () => { item.qty = Math.max(1, Math.min(20, item.qty + delta)); write(cart); render(); });
        return b;
      };
      qty.append(mk("−", -1), el("span", "w-6 text-center text-sm font-semibold", String(item.qty)), mk("+", 1));

      const rm = el("button", "text-slate-400 hover:text-red-600 text-sm", "Remove");
      rm.type = "button";
      rm.addEventListener("click", () => { write(cart.filter((c) => c.id !== item.id)); render(); });

      row.append(imgBox, info, qty, rm);
      list.appendChild(row);
    });
    $("cart-total").textContent = fmt(total);
  }

  $("checkout-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("pay-btn");
    const label = btn.textContent;
    btn.textContent = "Connecting to Paystack…";
    btn.disabled = true;
    const fd = new FormData(e.target);
    const payload = {
      items: read().map((i) => ({ product_id: i.id, qty: i.qty })),
      address: fd.get("address"),
      phone: fd.get("phone"),
    };
    try {
      const res = await fetch("/checkout", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
      if (res.redirected || res.status === 401) { location.href = "/login?next=/cart"; return; }
      const data = await res.json();
      // Only ever follow a redirect to Paystack's own checkout domain.
      if (res.ok && typeof data.authorization_url === "string" &&
          /^https:\/\/([a-z0-9-]+\.)?paystack\.(com|co)\//.test(data.authorization_url)) {
        localStorage.removeItem(KEY);
        location.href = data.authorization_url;
        return;
      }
      alert(data.error || "Something went wrong");
    } catch {
      alert("Server is busy. Please try again.");
    }
    btn.textContent = label;
    btn.disabled = false;
  });

  render();
})();
