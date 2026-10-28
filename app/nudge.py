"""Fleet-health nudges: LockSmith's inbox for the two-way leg
of Fleet Check.

Everything else in the fleet is pull — a stall waits to be called,
and a broken stall that never asks for a check never gets one. A
nudge is the opposite direction: a signed knock on a stall's own
door saying "this route of yours is broken in this specific way,
here is the probe evidence, and here is the check that found it."
Tonight it exists as an open convention plus our own inbox:

  * The convention (spec: x402-loop-kits/nudge-inbox.md): a stall
    publishes a nudge inbox in its discovery doc —
    extensions.nudge = {endpoint, accepts: ["fleet-health/v1"]} —
    and accepts POSTs of fleet-health-nudge messages. Every message
    is EIP-191-signed by the sender wallet over a canonical form of
    the message, so any stall can verify who knocked and that the
    evidence was not altered in transit.
  * Our inbox: POST /v1/nudge (FREE — inbound mail is not a product,
    and the priced route count does not move). Signature-verified,
    rate-limited per sender, deduped, stored in the sqlite store
    below. The owner reads it via POST /v1/internal/nudges, gated
    by the fleet internal secret exactly like /v1/internal/audit.
  * Opt-out: a stall stops nudges by POSTing a fleet-health-opt-out
    message signed by the wallet its own discovery doc publishes
    as payTo — control of the payTo is control of the stall's mail.

This module only receives. Behaviour mirrors StallRow's
app/services/nudge.py exactly; the store lives here because this
service has no persistent store of its own.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from eth_account import Account
from eth_account.messages import encode_defunct

PROTOCOL = "fleet-health/v1"
KIND_NUDGE = "fleet-health-nudge"
KIND_OPT_OUT = "fleet-health-opt-out"
SPEC_URL = "https://github.com/QuincyGB/x402-loop-kits/blob/main/nudge-inbox.md"

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_SIGNATURE_RE = re.compile(r"^0x[0-9a-fA-F]{130}$")
_MAX_EVIDENCE_BYTES = 32_768
_MAX_FIELD_CHARS = 512


class NudgeError(ValueError):
    """A nudge that must be refused with a clean 4xx. `http_status`
    is 400 for malformed messages and 403 for signatures that do not
    verify against the claimed sender."""

    def __init__(self, message: str, http_status: int = 400):
        super().__init__(message)
        self.http_status = http_status


def canonical_text(message: dict) -> str:
    """The exact text a sender signs: the protocol line, then the
    message WITHOUT its signature field as canonical JSON (keys
    sorted recursively, no insignificant whitespace, UTF-8). Any
    implementation that reproduces this string reproduces the
    signature — the spec pins a worked example."""
    unsigned = {k: v for k, v in message.items() if k != "signature"}
    body = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return f"fleet-health-nudge/v1\n{body}"


def recover_signer(message: dict) -> str | None:
    """The address that signed `message`, or None when the signature
    is malformed or unrecoverable."""
    signature = message.get("signature")
    if not isinstance(signature, str) or not _SIGNATURE_RE.match(signature):
        return None
    try:
        return Account.recover_message(
            encode_defunct(text=canonical_text(message)), signature=signature
        )
    except Exception:  # noqa: BLE001 — a bad signature is data, not a crash
        return None


def _is_http_url(value) -> bool:
    if not isinstance(value, str) or len(value) > 2048:
        return False
    parts = urlsplit(value)
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _is_origin(value) -> bool:
    if not _is_http_url(value):
        return False
    parts = urlsplit(value)
    return parts.path in ("", "/") and not parts.query and not parts.fragment


def validate_message(message) -> dict:
    """Structural validation of one inbound message. Raises
    NudgeError (400) on anything malformed; returns the message
    unchanged on success. Signature verification is separate
    (verify_sender) so the two refusal classes stay distinct."""
    if not isinstance(message, dict):
        raise NudgeError("message must be a JSON object")
    kind = message.get("kind")
    if kind not in (KIND_NUDGE, KIND_OPT_OUT):
        raise NudgeError(f"unknown kind: {kind!r}")
    if message.get("protocol") != PROTOCOL:
        raise NudgeError(f"protocol must be {PROTOCOL!r}")
    if not _is_origin(message.get("stall")):
        raise NudgeError("stall must be an http(s) origin URL")
    sender = message.get("sender")
    if not isinstance(sender, str) or not _ADDRESS_RE.match(sender):
        raise NudgeError("sender must be an EVM address")
    signature = message.get("signature")
    if not isinstance(signature, str) or not _SIGNATURE_RE.match(signature):
        raise NudgeError("signature must be a 65-byte hex EIP-191 signature")
    if kind == KIND_NUDGE:
        route = message.get("route")
        if not _is_http_url(route):
            raise NudgeError("route must be an http(s) URL")
        stall = message["stall"].rstrip("/")
        if not route.startswith(stall + "/"):
            raise NudgeError("route must belong to the stall origin")
        defect = message.get("defect")
        if not isinstance(defect, dict):
            raise NudgeError("defect must be an object")
        code = defect.get("code")
        if not isinstance(code, str) or not code or len(code) > 64:
            raise NudgeError("defect.code must be a short non-empty string")
        for field in ("expected", "observed"):
            value = defect.get(field)
            if value is not None and not isinstance(value, (str, int)):
                raise NudgeError(f"defect.{field} must be a string, integer, or null")
            if isinstance(value, str) and len(value) > _MAX_FIELD_CHARS:
                raise NudgeError(f"defect.{field} is too long")
        evidence = message.get("evidence")
        if evidence is not None:
            if not isinstance(evidence, dict):
                raise NudgeError("evidence must be an object")
            if len(json.dumps(evidence).encode()) > _MAX_EVIDENCE_BYTES:
                raise NudgeError("evidence is too large")
        first_seen = message.get("first_seen")
        if not isinstance(first_seen, str) or not first_seen or len(first_seen) > 64:
            raise NudgeError("first_seen must be an ISO-8601 timestamp string")
        if not _is_http_url(message.get("check_url")):
            raise NudgeError("check_url must be an http(s) URL")
    return message


def verify_sender(message: dict) -> None:
    """The signature must recover to the claimed sender wallet.
    Raises NudgeError (403) otherwise."""
    signer = recover_signer(message)
    if signer is None:
        raise NudgeError("signature does not recover to an address", 403)
    if signer.lower() != str(message["sender"]).lower():
        raise NudgeError("signature was not made by the claimed sender", 403)


def dedupe_key(message: dict) -> str:
    """One knock per (sender, route, defect, first_seen): a re-sent
    identical nudge is a duplicate, not a second inbox entry. An
    escalation knock (spec §6) carries `escalation: "final"` and IS
    a distinct message from knock 1 despite sharing those four
    fields, so the marker joins the key when present — and only
    then, keeping pre-escalation keys byte-identical."""
    parts = [
        str(message["sender"]).lower(),
        str(message.get("route", "")),
        str((message.get("defect") or {}).get("code", "")),
        str(message.get("first_seen", "")),
    ]
    if message.get("escalation"):
        parts.append(str(message["escalation"]))
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def nudge_extension(base_url: str) -> dict:
    """The discovery-doc extension that publishes this stall's
    inbox — the convention's whole advertisement."""
    return {
        "endpoint": f"{base_url}/v1/nudge",
        "accepts": [PROTOCOL],
        "spec": SPEC_URL,
    }


# --- rate limiting -------------------------------------------------------------
# Per-sender sliding window over VERIFIED knocks (duplicates count:
# a re-send is still a knock). In-process, like the rest of this
# service's abuse brakes — a restart resets the window, and the
# durable backstop is that unique mail is stored and countable.
# LOCKSMITH_NUDGE_RATE_PER_HOUR tunes it (tests set it low).

def rate_limit_per_hour() -> int:
    try:
        return max(1, int(os.environ.get("LOCKSMITH_NUDGE_RATE_PER_HOUR", "30")))
    except ValueError:
        return 30


class _RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, sender: str, limit: int, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        key = sender.lower()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if t > now - 3600]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


RATE_LIMITER = _RateLimiter()


# --- store ---------------------------------------------------------------------
# The nudge store: signed inbound mail, stored verbatim in a small
# sqlite file, deduped on (sender, route, defect, first_seen).
# Opt-outs live beside the mail: a stall whose payTo signed an
# opt-out is never nudged again.
#
# Path resolution: LOCKSMITH_NUDGE_PATH wins; else a mounted /data
# volume; else a local file (ephemeral across redeploys, gitignored).

VOLUME_MOUNT_PATH = "/data"
NUDGE_FILENAME = "lock-nudges.db"

_isdir = os.path.isdir
_ismount = os.path.ismount
_writable = os.access


def resolve_nudge_path() -> str:
    explicit = os.environ.get("LOCKSMITH_NUDGE_PATH", "").strip()
    if explicit:
        return explicit
    if (
        _isdir(VOLUME_MOUNT_PATH)
        and _ismount(VOLUME_MOUNT_PATH)
        and _writable(VOLUME_MOUNT_PATH, os.W_OK)
    ):
        return os.path.join(VOLUME_MOUNT_PATH, NUDGE_FILENAME)
    return NUDGE_FILENAME


def _iso_of(epoch_seconds: float) -> str:
    return (
        datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


class NudgeStore:
    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nudges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dedupe_key TEXT NOT NULL UNIQUE,
                    sender TEXT NOT NULL,
                    stall TEXT NOT NULL,
                    route TEXT NOT NULL,
                    defect_code TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    received_epoch REAL NOT NULL,
                    message_json TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nudge_optouts (
                    stall TEXT PRIMARY KEY,
                    wallet TEXT NOT NULL,
                    received_epoch REAL NOT NULL
                )
                """
            )
            self._conn.commit()

    @property
    def path(self) -> str:
        return self._path

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def store_nudge(self, message: dict, dedupe_key: str) -> bool:
        """Store one verified nudge. Returns False when the dedupe
        key already exists — a re-sent identical nudge is a
        duplicate delivery, not a second entry."""
        now = time.time()
        defect = message.get("defect") or {}
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO nudges (dedupe_key, sender, "
                "stall, route, defect_code, first_seen, "
                "received_epoch, message_json) VALUES (?, ?, ?, ?, "
                "?, ?, ?, ?)",
                (
                    dedupe_key,
                    str(message["sender"]),
                    str(message["stall"]),
                    str(message.get("route", "")),
                    str(defect.get("code", "")),
                    str(message.get("first_seen", "")),
                    now,
                    json.dumps(message, sort_keys=True),
                ),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def nudge_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM nudges").fetchone()
        return int(row[0])

    def nudges_since(self, sender: str, since_epoch: float) -> int:
        """Verified nudges received from one sender after an epoch —
        the rate limiter's count (duplicates included: a re-send is
        still a knock)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM nudges WHERE lower(sender) = "
                "lower(?) AND received_epoch > ?",
                (sender, since_epoch),
            ).fetchone()
        return int(row[0])

    def list_nudges(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT received_epoch, message_json FROM nudges "
                "ORDER BY id DESC LIMIT ?",
                (max(1, min(int(limit), 500)),),
            ).fetchall()
        return [
            {
                "received_at": _iso_of(row[0]),
                "message": json.loads(row[1]),
            }
            for row in rows
        ]

    def record_optout(self, stall: str, wallet: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO nudge_optouts (stall, wallet, "
                "received_epoch) VALUES (?, ?, ?)",
                (stall.rstrip("/"), wallet, time.time()),
            )
            self._conn.commit()

    def list_optouts(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT stall, wallet, received_epoch FROM "
                "nudge_optouts ORDER BY stall"
            ).fetchall()
        return [
            {"stall": row[0], "wallet": row[1], "recorded_at": _iso_of(row[2])}
            for row in rows
        ]

    def is_opted_out(self, stall: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM nudge_optouts WHERE stall = ?",
                (stall.rstrip("/"),),
            ).fetchone()
        return row is not None
