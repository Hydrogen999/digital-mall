// static/js/chat.js
const socket = io();
const box = document.getElementById("messages");

function bubble(m) {
  const mine = m.sender_id === MY_ID;
  const el = document.createElement("div");
  el.className = `flex ${mine ? "justify-end" : "justify-start"}`;
  el.innerHTML = `
    <div class="max-w-[75%] px-3 py-2 rounded-2xl text-sm
      ${mine ? "bg-amber-500 text-white rounded-br-sm" : "bg-slate-100 text-slate-900 rounded-bl-sm"}">
      ${m.image ? `<img src="${m.image}" class="rounded-lg mb-1 max-h-40">` : ""}
      <div>${m.body ?? ""}</div>
      <div class="text-[10px] opacity-60 mt-1">${m.created_at ?? ""}</div>
    </div>`;
  box.appendChild(el);
  box.scrollTop = box.scrollHeight;
}

socket.on("connect", () => socket.emit("join", { conversation_id: CONV_ID }));
socket.on("new_message", bubble);

document.getElementById("send-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const input = document.getElementById("input");
  if (!input.value.trim()) return;
  socket.emit("send_message", { conversation_id: CONV_ID, body: input.value });
  input.value = "";
});