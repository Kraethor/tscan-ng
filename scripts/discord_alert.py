#!/usr/bin/env python3
"""
discord_alert.py

Minimal Discord webhook notification support for tscan-ng.

Purpose
-------
This module provides a deliberately minimal and isolated notification
mechanism for confirmed credential discoveries detected by watch.py.

Design Goals
------------
- Do NOT block packet processing or watch loops.
- Do NOT expose credentials to Discord.
- Do NOT raise exceptions back into watch.py.
- Keep the implementation intentionally simple for initial testing.
- Allow future expansion (cooldowns, embeds, dedupe, masking, queues).

Security Notes
--------------
This module intentionally sends ONLY a generic notification message:

    "Credential found"

No usernames, passwords, tokens, packet payloads, or stream metadata
are transmitted to Discord.

The local JSONL results remain the authoritative evidence source.

Configuration
-------------
Set discord_webhook in the [discord] section of tscan_ng.conf:

    [discord]
    discord_webhook = https://discord.com/api/webhooks/...

Usage
-----
from discord_alert import send_alert

send_alert()
"""

import configparser
import os

import requests

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "tscan_ng", "config", "tscan_ng.conf")


def _read_webhook() -> str:
    """
    Read the Discord webhook URL directly from tscan_ng.conf.

    Reads only the [discord] section via configparser, deliberately bypassing
    the full Config class and its _validate() checks. watch.py runs as a
    regular user who cannot write to /var/log/tscan, so full config validation
    would always fail even though alerting needs no write access.

    Returns:
        Webhook URL string, or empty string if unset or unreadable.
    """
    cfg = configparser.ConfigParser()
    cfg.read(os.path.abspath(_CONFIG_PATH))
    return cfg.get("discord", "discord_webhook", fallback="").strip()


# Discord webhook URL loaded from tscan_ng.conf [discord] section.
# If undefined or config is unreadable, alerting is silently disabled.
WEBHOOK_URL = _read_webhook()

def send_alert() -> None:
    """
    Send a minimal Discord alert.

    This function intentionally sends only a generic notification
    message to validate webhook functionality without exposing
    credential material.

    Failure Behavior
    ----------------
    All exceptions are intentionally suppressed to prevent
    Discord outages or network failures from impacting the
    tscan-ng monitoring pipeline.
    """

    # If no webhook is configured, do nothing.
    if not WEBHOOK_URL:
        return

    payload = {
        "content": "Credential found"
    }

    try:
        requests.post(
            WEBHOOK_URL,
            json=payload,
            timeout=5
        )

    except Exception:
        # Intentionally suppress all exceptions.
        #
        # Alerting failures must never impact watch.py
        # or the credential processing pipeline.
        pass
