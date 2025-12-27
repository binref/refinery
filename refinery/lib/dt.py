"""
Date and time related functoins.
"""
from __future__ import annotations

import datetime
import sys


def isodate(iso: str) -> datetime.datetime | None:
    """
    Convert an input date string in ISO format to a `datetime` object. Contains fallbacks for early
    Python versions.
    """
    if len(iso) not in range(16, 25):
        return None
    iso = iso[:19].replace(' ', 'T', 1)
    try:
        try:
            return datetime.datetime.fromisoformat(iso)
        except AttributeError:
            return datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def date_from_timestamp(ts: int | float):
    """
    Convert a UTC timestamp to a datetime object.
    """
    if sys.version_info >= (3, 12):
        dt = datetime.datetime.fromtimestamp(ts, datetime.UTC)
    else:
        dt = datetime.datetime.utcfromtimestamp(ts)
    return dt.replace(tzinfo=None)
