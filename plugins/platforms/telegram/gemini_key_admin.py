"""Secure Gemini API key management via Telegram (``/gemini-key``, ``/gemini-keys``).

Deterministic, code-only command handlers — never routed through the LLM
(the model never sees a raw key and cannot be asked to "save" one). Reuses
the existing credential pool (``agent.credential_pool``) exactly the way the
dashboard's manual add-credential endpoint does
(``hermes_cli/web_routers/ops.py: POST /api/credentials/pool``), and reuses
the existing Telegram allowlist machinery (``TELEGRAM_ALLOWED_USERS`` /
``allow_from``) rather than inventing a new auth mechanism.

Persistence: ``pool.add_entry`` writes through ``write_credential_pool``,
the same on-disk pool store every other credential (env-seeded or manual)
uses under ``HERMES_HOME`` — so an added key survives process restarts and
Railway redeploys as long as the volume backing ``HERMES_HOME`` is mounted.
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid

logger = logging.getLogger(__name__)

GEMINI_PROVIDER = "gemini"

# Google is migrating Gemini API keys from legacy "Standard" keys (``AIza...``)
# to "Auth" keys (``AQ.Ab...``). As of September 2026 Standard keys are
# rejected outright, so newly-issued keys will be AQ.-shaped; both patterns
# are accepted so an already-issued Standard key (e.g. a restricted one still
# inside its grace period) keeps working too.
_GEMINI_KEY_RE = re.compile(r"^(AQ\.[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{30,})$")


def is_valid_gemini_key(candidate: str) -> bool:
    """True if ``candidate`` looks like a Gemini Auth (AQ.) or Standard (AIza) key."""
    return bool(_GEMINI_KEY_RE.match((candidate or "").strip()))


def _mask(token: str) -> str:
    from hermes_cli.config import redact_key
    return redact_key(token or "")


def _explicit_allowlist_authorized(adapter, msg) -> bool:
    """True only when the sender is EXPLICITLY named in ``TELEGRAM_ALLOWED_USERS``
    (or the adapter's ``allow_from``/``group_allow_from`` config) for this chat.

    Deliberately does not fall back to ``TELEGRAM_ALLOW_ALL_USERS`` /
    ``GATEWAY_ALLOW_ALL_USERS``: credential management must stay gated even
    when the bot is otherwise configured to accept everyone (req. #7).
    """
    source = adapter._source_from_message_for_auth(msg)
    user_id = source.user_id
    if not user_id:
        return False
    adapter_allow_from = adapter.config.extra.get(
        "group_allow_from" if (source.chat_type or "") in ("group", "forum", "channel") else "allow_from")
    if adapter_allow_from is not None:
        from gateway.authz_mixin import _coerce_allow_set
        allowed = _coerce_allow_set(adapter_allow_from)
        return user_id in allowed or "*" in allowed
    decision = adapter._env_allowlist_decision(user_id)
    return bool(decision)


def _command_args(msg) -> str:
    text = (getattr(msg, "text", "") or "").strip()
    parts = text.split(maxsplit=1)
    return parts[1].strip() if len(parts) > 1 else ""


async def _reply(msg, text: str) -> None:
    try:
        await msg.reply_text(text)
    except Exception:
        logger.warning("[Telegram] Failed to send gemini-key admin reply", exc_info=True)


def _add_key_sync(key: str):
    """Runs off the event loop: pool I/O is blocking file access."""
    from agent.credential_pool import AUTH_TYPE_API_KEY, SOURCE_MANUAL, PooledCredential, load_pool

    pool = load_pool(GEMINI_PROVIDER)
    for entry in pool.entries():
        if entry.access_token == key:
            return pool, entry, True
    entry = pool.add_entry(PooledCredential(
        provider=GEMINI_PROVIDER,
        id=uuid.uuid4().hex[:6],
        label=f"telegram-{uuid.uuid4().hex[:6]}",
        auth_type=AUTH_TYPE_API_KEY,
        priority=0,
        source=SOURCE_MANUAL,
        access_token=key,
    ))
    return pool, entry, False


def _list_keys_sync():
    from agent.credential_pool import load_pool
    return load_pool(GEMINI_PROVIDER).entries()


async def handle_gemini_key_command(adapter, msg) -> None:
    """``/gemini-key <API_KEY>`` — add a Gemini credential to the existing pool."""
    if not _explicit_allowlist_authorized(adapter, msg):
        logger.warning("[Telegram] Unauthorized /gemini-key attempt")
        await _reply(msg, "\u26d4 You are not authorized to manage Gemini API keys.")
        return

    key = _command_args(msg)
    if not key:
        await _reply(msg, "Usage: /gemini-key <GEMINI_API_KEY>")
        return
    if not is_valid_gemini_key(key):
        # Never echo the invalid input back — it may still be a near-miss real secret.
        await _reply(msg, "\u274c Gemini API key could not be added.")
        return

    try:
        pool, entry, was_duplicate = await asyncio.to_thread(_add_key_sync, key)
    except Exception:
        logger.exception("[Telegram] Failed to add Gemini API key")
        await _reply(msg, "\u274c Gemini API key could not be added.")
        return

    masked = _mask(entry.access_token)
    if was_duplicate:
        await _reply(msg, f"\u26a0\ufe0f This Gemini API key is already registered.\nID: {masked}")
    else:
        await _reply(
            msg,
            f"\u2705 Gemini API key added successfully.\nID: {masked}\nTotal Gemini keys: {len(pool.entries())}",
        )


async def handle_gemini_keys_command(adapter, msg) -> None:
    """``/gemini-keys`` — masked status listing, never the raw keys."""
    if not _explicit_allowlist_authorized(adapter, msg):
        await _reply(msg, "\u26d4 You are not authorized to view Gemini API keys.")
        return

    try:
        entries = await asyncio.to_thread(_list_keys_sync)
    except Exception:
        logger.exception("[Telegram] Failed to list Gemini API keys")
        await _reply(msg, "\u274c Could not read Gemini credentials.")
        return

    if not entries:
        await _reply(msg, "No Gemini API keys registered yet.")
        return

    lines = ["## Gemini Keys", ""]
    for i, entry in enumerate(entries, start=1):
        status = "active" if not entry.last_status else "unavailable"
        lines.append(f"{i}. {_mask(entry.access_token)} \u2014 {status}")
    await _reply(msg, "\n".join(lines))


async def maybe_handle_gemini_key_command(adapter, msg) -> bool:
    """Intercept point for the adapter's command dispatch.

    Returns True when ``msg`` was a Gemini-key admin command (handled here,
    short-circuiting the normal LLM-bound dispatch); False otherwise.
    """
    text = (getattr(msg, "text", "") or "").strip()
    if not text.startswith("/"):
        return False
    cmd = text.split(maxsplit=1)[0][1:].split("@", 1)[0].lower()
    if cmd == "gemini-key":
        await handle_gemini_key_command(adapter, msg)
        return True
    if cmd == "gemini-keys":
        await handle_gemini_keys_command(adapter, msg)
        return True
    return False
