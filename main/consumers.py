import json
from datetime import datetime, timezone

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from .db import query_one
from .views import ensure_chat_table, get_chat_lock


def _coerce_iso(dt_val):
    if isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            dt_val = dt_val.replace(tzinfo=timezone.utc)
        return dt_val.isoformat()
    return None


@database_sync_to_async
def _get_user_name(user_id: str) -> str:
    row = query_one("SELECT name FROM users WHERE user_id = %s", (user_id,))
    return (row or {}).get("name") or user_id


@database_sync_to_async
def _get_parent_info(reply_to_id: int | None) -> dict:
    if not reply_to_id:
        return {"parent_user_name": None, "parent_body": None}
    row = query_one(
        """
        SELECT m.body AS parent_body,
               COALESCE(u.name, m.user_id) AS parent_user_name
        FROM chat_messages m
        LEFT JOIN users u ON u.user_id = m.user_id
        WHERE m.id = %s
        """,
        (reply_to_id,),
    )
    return {
        "parent_user_name": (row or {}).get("parent_user_name"),
        "parent_body": (row or {}).get("parent_body"),
    }


@database_sync_to_async
def _insert_message(user_id: str, body: str, image_base64: str | None, reply_to_id: int | None):
    ensure_chat_table()
    row = query_one(
        """
        INSERT INTO chat_messages (user_id, body, image_base64, reply_to_id)
        VALUES (%s, %s, %s, %s)
        RETURNING id, created_at
        """,
        (user_id, body, image_base64, reply_to_id),
    )
    return row or {}


@database_sync_to_async
def _is_chat_locked_for_session(session) -> bool:
    lock = get_chat_lock()
    if not lock.get("locked"):
        return False
    return not session.get("chat_unlocked")


class ChatConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        session = self.scope.get("session")
        self.user_id = session.get("user_id") if session else None
        if not self.user_id:
            await self.close(code=4401)
            return

        self.user_name = session.get("user_name") if session else None
        self.chat_id = "community"
        self.group_name = f"chat_{self.chat_id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        print(f"[ws] chat connected user_id={self.user_id}")
        await self.send_json(
            {
                "event": "connection.ready",
                "data": {"chatId": self.chat_id, "userId": self.user_id},
            }
        )

    async def disconnect(self, close_code):
        try:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        except Exception:
            pass
        print(f"[ws] chat disconnected user_id={getattr(self, 'user_id', None)} code={close_code}")

    async def receive_json(self, content, **kwargs):
        event = (content or {}).get("event")
        data = (content or {}).get("data") or {}

        if event in {"auth", "identify"}:
            await self.send_json({"event": "auth.ok", "data": {"userId": self.user_id}})
            return

        if event == "ping":
            await self.send_json({"event": "pong", "data": {"ts": datetime.now(timezone.utc).isoformat()}})
            return

        if event == "typing":
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "chat.typing",
                    "payload": {
                        "event": "typing",
                        "data": {
                            "chatId": self.chat_id,
                            "userId": self.user_id,
                            "typing": bool(data.get("typing")),
                        },
                    },
                },
            )
            return

        if event == "read.receipt":
            return

        if event == "message.send":
            await self._handle_message_send(data)
            return

        await self.send_json({"event": "error", "data": {"message": "Unknown event"}})

    async def _handle_message_send(self, data: dict):
        temp_id = data.get("tempId")
        body = (data.get("text") or "").strip()
        image_base64 = data.get("imageBase64")
        reply_to_id = data.get("replyToId")
        if isinstance(reply_to_id, str) and reply_to_id.isdigit():
            reply_to_id = int(reply_to_id)
        if not isinstance(reply_to_id, int):
            reply_to_id = None

        if await _is_chat_locked_for_session(self.scope.get("session")):
            await self.send_json(
                {"event": "message.error", "data": {"tempId": temp_id, "error": "Chat is locked."}}
            )
            return

        if not body and not image_base64:
            await self.send_json(
                {"event": "message.error", "data": {"tempId": temp_id, "error": "Message is empty."}}
            )
            return

        if body and len(body) > 1000:
            await self.send_json(
                {"event": "message.error", "data": {"tempId": temp_id, "error": "Message too long."}}
            )
            return

        if image_base64 and len(image_base64) > 2 * 1024 * 1024 * 2:
            await self.send_json(
                {"event": "message.error", "data": {"tempId": temp_id, "error": "Image too large."}}
            )
            return

        user_name = self.user_name or await _get_user_name(self.user_id)
        inserted = await _insert_message(self.user_id, body, image_base64, reply_to_id)
        msg_id = inserted.get("id")
        created_at_iso = _coerce_iso(inserted.get("created_at")) or datetime.now(timezone.utc).isoformat()
        parent_info = await _get_parent_info(reply_to_id)

        message = {
            "id": msg_id,
            "tempId": temp_id,
            "chatId": self.chat_id,
            "senderId": self.user_id,
            "text": body,
            "createdAt": created_at_iso,
            "status": "sent",
            "userName": user_name,
            "replyToId": reply_to_id,
            "parentUserName": parent_info.get("parent_user_name"),
            "parentBody": parent_info.get("parent_body"),
            "imageBase64": image_base64,
        }

        await self.send_json(
            {
                "event": "message.ack",
                "data": {"tempId": temp_id, "id": msg_id, "createdAt": created_at_iso},
            }
        )

        await self.channel_layer.group_send(
            self.group_name,
            {"type": "chat.message", "payload": {"event": "message.new", "data": {"message": message}}},
        )

    async def chat_message(self, event):
        await self.send_json(event.get("payload", {}))

    async def chat_typing(self, event):
        await self.send_json(event.get("payload", {}))
