from copy import deepcopy


def deduplicate_and_order(messages):
    """Deduplicate by id (fallback tempId) and sort by createdAt ascending."""
    seen = {}
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        key = msg.get("id") or msg.get("tempId")
        if key is None:
            continue
        seen[str(key)] = deepcopy(msg)
    return sorted(seen.values(), key=lambda m: m.get("createdAt") or "")


def apply_ack(messages, temp_id, real_id, created_at=None):
    """Update optimistic message with server ack mapping and sent status."""
    updated = []
    for msg in messages:
        if not isinstance(msg, dict):
            updated.append(msg)
            continue
        if msg.get("id") == temp_id or msg.get("tempId") == temp_id:
            next_msg = deepcopy(msg)
            next_msg["id"] = real_id
            next_msg["status"] = "sent"
            if created_at:
                next_msg["createdAt"] = created_at
            updated.append(next_msg)
        else:
            updated.append(deepcopy(msg))
    return updated
