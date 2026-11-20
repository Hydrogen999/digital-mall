/* Chat client. Message text is ALWAYS inserted with textContent, never innerHTML,
   so a malicious message can't run script in the other person's browser. */
(function () {
  "use strict";
  const root = document.getElementById("chat-root");
  const CONV_ID = parseInt(root.dataset.convId, 10);
  const MY_ID = parseInt(root.dataset.myId, 10);
  const box = document.getElementById("messages");
  const seen = new Set();

  function bubble(m) {
    if (m.id != null) { if (seen.has(m.id)) return; seen.add(m.id); }
    const mine = m.sender_id === MY_ID;
    const row = document.createElement("div");
    row.className = "flex " + (mine ? "justify-end" : "justify-start");
    const inner = document.createElement("div");
    inner.className = "max-w-[75%] px-3 py-2 rounded-2xl text-sm break-words " +
      (mine ? "bg-amber-500 text-white rounded-br-sm" : "bg-slate-100 text-slate-900 rounded-bl-sm");
    const body = document.createElement("div");
    body.className = "whitespace-pre-wrap";
    body.textContent = m.body == null ? "" : String(m.body);
    const time = document.createElement("div");
    time.className = "text-[10px] opacity-60 mt-1";
    time.textContent = m.created_at == null ? "" : String(m.created_at);
    inner.append(body, time);
    row.appendChild(inner);
    box.appendChild(row);
    box.scrollTop = box.scrollHeight;
  }

  // Earlier messages are embedded as inert JSON (not executable), then rendered safely.
  try { JSON.parse(document.getElementById("chat-history").textContent).forEach(bubble); } catch (e) { /* no history */ }

  const socket = io();
  socket.on("connect", () => socket.emit("join", { conversation_id: CONV_ID }));
  socket.on("new_message", bubble);
  socket.on("rate_limited", (d) => alert((d && d.error) || "Slow down a little."));

  document.getElementById("send-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const input = document.getElementById("input");
    const text = input.value.trim();
    if (!text) return;
    socket.emit("send_message", { conversation_id: CONV_ID, body: text.slice(0, 1000) });
    input.value = "";
  });
})();
