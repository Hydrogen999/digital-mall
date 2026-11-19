from flask_socketio import SocketIO, emit, join_room
from models import db, Message, Conversation, Shop, User
from flask_login import current_user

socketio = SocketIO(cors_allowed_origins="*")

@socketio.on("join")
def on_join(data):
    """data: {conversation_id}"""
    if not current_user.is_authenticated:
        return
    conv = Conversation.query.get(data["conversation_id"])
    if not conv:
        return
    # Security: only the customer or the shop owner may join
    if current_user.id not in (conv.customer_id, conv.shop.owner_id):
        return
    join_room(f"conv_{conv.id}")
    # Mark messages as read for this user
    for m in conv.messages:
        if m.sender_id != current_user.id:
            m.is_read = True
    db.session.commit()

@socketio.on("send_message")
def on_message(data):
    """data: {conversation_id, body, image?}"""
    if not current_user.is_authenticated:
        return
    conv = Conversation.query.get(data["conversation_id"])
    if not conv or current_user.id not in (conv.customer_id, conv.shop.owner_id):
        return
    msg = Message(
        conversation_id=conv.id,
        sender_id=current_user.id,
        body=data.get("body", "").strip(),
        image=data.get("image"),
    )
    db.session.add(msg)
    db.session.commit()
    emit("new_message", {
        "id": msg.id,
        "body": msg.body,
        "image": msg.image,
        "sender_id": msg.sender_id,
        "sender_name": current_user.username,
        "created_at": msg.created_at.strftime("%H:%M"),
    }, room=f"conv_{conv.id}")