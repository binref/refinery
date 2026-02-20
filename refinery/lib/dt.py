"""
Date and time related functoins.
"""
from __future__ import annotations

import sys

from datetime import datetime, timezone


def isodate(iso: str) -> datetime | None:
    """
    Convert an input date string in ISO format to a `datetime` object. Contains fallbacks for early
    Python versions.
    """
    if len(iso) not in range(16, 25):
        return None
    iso = iso[:19].replace(' ', 'T', 1)
    try:
        try:
            return datetime.fromisoformat(iso)
        except AttributeError:
            return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def date_from_timestamp(ts: int | float):
    """
    Convert a UTC timestamp to a datetime object.
    """
    if sys.version_info >= (3, 12):
        dt = datetime.fromtimestamp(ts, timezone.utc)
    else:
        dt = datetime.utcfromtimestamp(ts)
    return dt.replace(tzinfo=None)


def dostime(stamp: int) -> datetime:
    """
    Parses a given DOS timestamp into a datetime object.
    """
    d, t = stamp >> 16, stamp & 0xFFFF
    s = (t & 0x1F) << 1

    return datetime(
        year   = ((d & 0xFE00) >> 0x9) + 1980,  # noqa
        month  = ((d & 0x01E0) >> 0x5),         # noqa
        day    = ((d & 0x001F) >> 0x0),         # noqa
        hour   = ((t & 0xF800) >> 0xB),         # noqa
        minute = ((t & 0x07E0) >> 0x5),         # noqa
        second = 59 if s == 60 else s,          # noqa
    )
