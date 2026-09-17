"""Tests for Telegram Gemini credential management (/gemini-key, /gemini-keys).

Covers: valid key add, duplicate detection, unauthorized user, format
validation (new AQ. Auth keys and legacy AIza Standard keys), persistence
across ``load_pool`` reloads, full-key-never-in-reply, and pool registration.
"""
from types import SimpleNamespace

import pytest

from gateway.config import Platform, PlatformConfig
from plugins.platforms.telegram.gemini_key_admin import (
    is_valid_gemini_key,
    maybe_handle_gemini_key_command,
)

AQ_KEY = "AQ.Ab8W9xJk2NpQrStUvWxYz0123456789abcdefGHIJK"
AIZA_KEY = "AIzaSyD_EXAMPLE1234567890abcdefghijklmno"


def _adapter(extra=None):
    from plugins.platforms.telegram.adapter import TelegramAdapter

    adapter = object.__new__(TelegramAdapter)
    adapter.platform = Platform.TELEGRAM
    adapter.config = PlatformConfig(enabled=True, token="***", extra=extra or {})
    adapter._bot = SimpleNamespace(id=999, username="hermes_bot")
    return adapter


class _Msg:
    def __init__(self, text, user_id=111):
        self.text = text
        self.caption = None
        self.from_user = SimpleNamespace(id=user_id, username="alice", full_name="Alice", is_bot=False)
        self.chat = SimpleNamespace(id=user_id, type="private", is_forum=False)
        self.message_thread_id = None
        self.is_topic_message = False
        self.replies = []

    async def reply_text(self, text, **kwargs):
        self.replies.append(text)


@pytest.fixture
def hermes_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    yield tmp_path


def test_key_format_accepts_both_shapes():
    assert is_valid_gemini_key(AQ_KEY) is True
    assert is_valid_gemini_key(AIZA_KEY) is True
    assert is_valid_gemini_key("not-a-key") is False
    assert is_valid_gemini_key("") is False


@pytest.mark.asyncio
async def test_valid_key_add_registers_in_pool(hermes_home, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "111")
    adapter = _adapter()
    msg = _Msg(f"/gemini-key {AQ_KEY}")

    handled = await maybe_handle_gemini_key_command(adapter, msg)

    assert handled is True
    assert any("added successfully" in r for r in msg.replies)
    assert AQ_KEY not in "".join(msg.replies)  # full key never echoed

    from agent.credential_pool import load_pool
    entries = load_pool("gemini").entries()
    assert len(entries) == 1
    assert entries[0].access_token == AQ_KEY


@pytest.mark.asyncio
async def test_duplicate_key_is_reported_not_readded(hermes_home, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "111")
    adapter = _adapter()
    await maybe_handle_gemini_key_command(adapter, _Msg(f"/gemini-key {AQ_KEY}"))

    msg2 = _Msg(f"/gemini-key {AQ_KEY}")
    await maybe_handle_gemini_key_command(adapter, msg2)

    assert any("already registered" in r for r in msg2.replies)
    from agent.credential_pool import load_pool
    assert len(load_pool("gemini").entries()) == 1


@pytest.mark.asyncio
async def test_multiple_keys_all_registered(hermes_home, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "111")
    adapter = _adapter()
    second_key = AIZA_KEY
    await maybe_handle_gemini_key_command(adapter, _Msg(f"/gemini-key {AQ_KEY}"))
    await maybe_handle_gemini_key_command(adapter, _Msg(f"/gemini-key {second_key}"))

    from agent.credential_pool import load_pool
    tokens = {e.access_token for e in load_pool("gemini").entries()}
    assert tokens == {AQ_KEY, second_key}


@pytest.mark.asyncio
async def test_unauthorized_user_is_rejected(hermes_home, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "222")  # not our sender
    adapter = _adapter()
    msg = _Msg(f"/gemini-key {AQ_KEY}", user_id=111)

    handled = await maybe_handle_gemini_key_command(adapter, msg)

    assert handled is True
    assert any("not authorized" in r for r in msg.replies)
    from agent.credential_pool import load_pool
    assert load_pool("gemini").entries() == []


@pytest.mark.asyncio
async def test_allow_all_does_not_grant_credential_management(hermes_home, monkeypatch):
    """TELEGRAM_ALLOW_ALL_USERS opens ordinary chat access but must NOT open
    credential management — only an explicit TELEGRAM_ALLOWED_USERS entry does."""
    monkeypatch.setenv("TELEGRAM_ALLOW_ALL_USERS", "true")
    monkeypatch.delenv("TELEGRAM_ALLOWED_USERS", raising=False)
    adapter = _adapter()
    msg = _Msg(f"/gemini-key {AQ_KEY}", user_id=111)

    await maybe_handle_gemini_key_command(adapter, msg)

    assert any("not authorized" in r for r in msg.replies)


@pytest.mark.asyncio
async def test_invalid_key_rejected_and_never_echoed(hermes_home, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "111")
    adapter = _adapter()
    msg = _Msg("/gemini-key totally-not-a-gemini-key")

    await maybe_handle_gemini_key_command(adapter, msg)

    assert any("could not be added" in r for r in msg.replies)
    assert "totally-not-a-gemini-key" not in "".join(msg.replies)


@pytest.mark.asyncio
async def test_persistence_after_reload(hermes_home, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "111")
    adapter = _adapter()
    await maybe_handle_gemini_key_command(adapter, _Msg(f"/gemini-key {AQ_KEY}"))

    from agent.credential_pool import load_pool
    # Simulate a fresh process: load_pool() re-reads from the on-disk pool store.
    reloaded = load_pool("gemini")
    assert [e.access_token for e in reloaded.entries()] == [AQ_KEY]


@pytest.mark.asyncio
async def test_existing_env_key_still_seeded_alongside_manual_keys(hermes_home, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "111")
    monkeypatch.setenv("GEMINI_API_KEY", AIZA_KEY)
    adapter = _adapter()
    await maybe_handle_gemini_key_command(adapter, _Msg(f"/gemini-key {AQ_KEY}"))

    from agent.credential_pool import load_pool
    tokens = {e.access_token for e in load_pool("gemini").entries()}
    assert AIZA_KEY in tokens  # env-seeded key untouched
    assert AQ_KEY in tokens    # manually-added key present too


@pytest.mark.asyncio
async def test_gemini_keys_status_is_masked(hermes_home, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "111")
    adapter = _adapter()
    await maybe_handle_gemini_key_command(adapter, _Msg(f"/gemini-key {AQ_KEY}"))

    msg = _Msg("/gemini-keys")
    handled = await maybe_handle_gemini_key_command(adapter, msg)

    assert handled is True
    out = "".join(msg.replies)
    assert "Gemini Keys" in out
    assert AQ_KEY not in out
    assert "active" in out


@pytest.mark.asyncio
async def test_non_gemini_commands_are_not_intercepted(hermes_home, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "111")
    adapter = _adapter()
    msg = _Msg("/status")

    handled = await maybe_handle_gemini_key_command(adapter, msg)

    assert handled is False
    assert msg.replies == []
