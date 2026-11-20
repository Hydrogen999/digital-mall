import os

from flask_login import current_user
from flask_socketio import SocketIO, emit, join_room

from models import Conversation, Message, db
from security import limiter

MAX_MESSAGE_LEN = 1000

# Same-origin only by default. If the site is served from several origins
# (e.g. a custom domain + onrender.com), list them: ALLOWED_ORIGINS="https://a.com,https://b.com"
_origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
socketio = SocketIO(cors_allowed_origins=_origins or None, max_http_buffer_size=16 * 1024)


def _conversation_for(data):
    """Return the conversation if `data` is well-formed and the caller is a participant."""
    if not current_user.is_authenticated or not isinstance(data, dict):
        return None
    try:
        conv_id = int(data.get("conversation_id"))
    except (TypeError, ValueError):
        return None
    conv = db.session.get(Conversation, conv_id)
    if not conv:
        return None
    if current_user.id not in (conv.customer_id, conv.shop.owner_id):
        return None
    return conv


@socketio.on("join")
def on_join(data):
    conv = _conversation_for(data)
    if not conv:
        return
    join_room(f"conv_{conv.id}")
    for m in conv.messages:
        if m.sender_id != current_user.id and not m.is_read:
            m.is_read = True
    db.session.commit()


@socketio.on("send_message")
def on_message(data):
    conv = _conversation_for(data)
    if not conv:
        return
    body = data.get("body")
    if not isinstance(body, str):
        return
    body = body.strip()
    if not body or len(body) > MAX_MESSAGE_LEN:
        return
    # 20 messages / 30 s per user
    if not limiter.allow(f"chat:{current_user.id}", 20, 30):
        emit("rate_limited", {"error": "You're sending messages too quickly."})
        return

    # NOTE: the client-supplied "image" field is intentionally ignored; accepting an
    # arbitrary URL here would allow tracking pixels and hot-linked abuse.
    msg = Message(conversation_id=conv.id, sender_id=current_user.id, body=body)
    db.session.add(msg)
    db.session.commit()
    emit("new_message", {
        "id": msg.id,
        "body": msg.body,
        "image": None,
        "sender_id": msg.sender_id,
        "sender_name": current_user.username,
        "created_at": msg.created_at.strftime("%H:%M"),
    }, room=f"conv_{conv.id}")
