"""Periodic retraining of protected endpoints: the server asks the agent (0.3.13+) for two fresh, whole days of
activity (config refresh_days); the agent uploads them like its baseline; ingesting them queues a retraining on the
most recent days plus the analysts' false-alarm verdicts (worker.write_feedback_day)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from . import db

MIN_AGENT = (0, 3, 13)


def capable(agent_version) -> bool:
    try:
        return tuple(int(x) for x in str(agent_version or "").split(".")) >= MIN_AGENT
    except ValueError:
        return False


def request_refresh(c, eid: str, cfg: dict, why: str) -> list[str]:
    tz = ZoneInfo((cfg or {}).get("tz") or "UTC")
    d0 = datetime.now(tz).date()
    days = [str(d0 + timedelta(days=k)) for k in (1, 2)]      # whole future days: the agent keeps them for upload
    db.q(c, "UPDATE endpoints SET config = config || jsonb_build_object('refresh_days', %s::jsonb, 'refresh_reason', %s::text) WHERE id=%s",
         (json.dumps(days), why, eid))
    return days
