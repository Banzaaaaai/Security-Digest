"""Timezone-aware report boundaries and a DST-safe Actions guard."""

from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo


def window(config, kind, period=None, now=None):
    now = now or datetime.now(UTC)
    local = now.astimezone(ZoneInfo(config.settings["timezone"]))
    if kind == "daily":
        day = date.fromisoformat(period) if period else local.date()
        end = (
            now
            if day == local.date()
            else datetime.combine(day + timedelta(days=1), time(), local.tzinfo).astimezone(UTC)
        )
        return end - timedelta(hours=24), end, day.isoformat()
    if not period and config.settings["weekly"]["window"] == "rolling":
        return now - timedelta(days=7), now, local.strftime("%G-W%V")
    if period:
        year, week = map(int, period.split("-W"))
        monday = date.fromisocalendar(year, week, 1)
    else:
        monday = local.date() - timedelta(days=local.weekday() + 7)
    start = datetime.combine(monday, time(), local.tzinfo)
    return start.astimezone(UTC), (start + timedelta(days=7)).astimezone(UTC), monday.strftime("%G-W%V")


def schedule_allowed(config, kind, now=None, manual=False):
    if manual:
        return True
    if not config.settings["scheduling"]["enabled"]:
        return False
    local = (now or datetime.now(UTC)).astimezone(ZoneInfo(config.settings["timezone"]))
    return local.hour == config.settings["scheduling"][f"{kind}_hour"] and (
        kind != "weekly" or local.weekday() == 0
    )
