"""
Date and time related functoins.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


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


def pdfdate(value: str) -> datetime | None:
    """
    Parse a PDF date string in the ISO 32000 format `D:YYYYMMDDHHmmSS+hh'mm'`. The result is a
    timezone-aware `datetime` when the string specifies a UTC offset, and naive otherwise.
    """
    import re
    iso32 = R'D?:?(\d{4})' + 5 * R'(\d{2})?' + R'(?:([Zz+-])(\d{2})?\'?(\d{2})?\'?)?'
    if (match := re.match(iso32, value.strip())) is None:
        return None
    *dt, sgn, tzh, tzm = match.groups()
    parsed = [int(g) for g in dt if g is not None]
    while len(parsed) < 3:
        parsed.append(1)
    if sgn is None:
        tzinfo = None
    elif sgn in 'Zz':
        tzinfo = timezone.utc
    else:
        offset = timedelta(hours=int(tzh or 0), minutes=int(tzm or 0))
        tzinfo = timezone(offset if sgn == '+' else -offset)
    try:
        return datetime(*parsed, tzinfo=tzinfo)
    except ValueError:
        return None


def date_from_timestamp(ts: int | float):
    """
    Convert a UTC timestamp to a datetime object.
    """
    return datetime.fromtimestamp(ts, timezone.utc).replace(tzinfo=None)


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
