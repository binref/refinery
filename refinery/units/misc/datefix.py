from __future__ import annotations

import re

from datetime import datetime, timedelta

from refinery.lib.decorators import unicoded
from refinery.lib.tools import date_from_timestamp
from refinery.lib.types import Param
from refinery.units import Arg, Unit

_DATETIME_PATTERNS = {
    '%m/%d/%Y',
    '%a %b %d %Y %H:%M:%S',
    '%Y:%m:%d %H:%M:%S',
}
for comma in (',', ''):
    _DATETIME_PATTERNS.add(F'%m/%d/%Y{comma} %H:%M:%S')
    for month_name in ('%B', '%b'):
        for suffix in ('st', 'nd', 'rd', 'th', ''):
            _DATETIME_PATTERNS.add(F'{month_name} %d{suffix} %Y{comma} %H:%M:%S')
            _DATETIME_PATTERNS.add(F'{month_name} %d{comma} %Y')
            for day_name in ('%a', '%A'):
                # Wed, 20 Aug 2025 00:56:59
                _DATETIME_PATTERNS.add(F'{day_name}{comma} %d{suffix} {month_name} %Y %H:%M:%S')
                # Wed Mar 31 00:00:00 UTC 2027
                _DATETIME_PATTERNS.add(F'{day_name}{comma} {month_name} %d{suffix} %Y %H:%M:%S')
                _DATETIME_PATTERNS.add(F'{day_name}{comma} {month_name} %d{suffix} %H:%M:%S %Y')

for timesep in ('T', ' '):
    for millisecs in ('Z%f', '.%f', ''):
        _DATETIME_PATTERNS.add(F'%Y-%m-%d{timesep}%H:%M:%S{millisecs}')

_DATETIME_PATTERNS = sorted(_DATETIME_PATTERNS)
_TIMEZONE_PATTERN = R'''(?x)(?:
    (?:\(?(?:GMT|UTC)\)?)?
    (?P<info>
        (?P<p> [+-] )
        (?P<h> \d\d ):? (?![-T]|\s\d)
        (?P<m> \d\d )?
        (?:\s\([A-Z]{2,6}\))?
    )|
    (?P<name>\(?(?:GMT|UTC)\)?)
)
'''


class datefix(Unit):
    """
    Parses all kinds of date formats and unifies them into the same format. The unit expects the
    input to be a numeric timestamp or a string that specifies a date & time. It then outputs a
    unified representation of that timestamp, using ISO format by default. If you want to use this
    to normalize date strings in a piece of text, use the following pattern:

        emit ... | resub (??date) {0:datefix}

    This will use the `refinery.resub` unit to search for date-like strings in the input and use
    the `refinery.datefix` unit to convert them. You can also specify a format like so:

        emit ... | resub (??date) {0:datefix[%H:%M:%S]}

    The above pipeline will convert all date-like strings in the input to their time value in ISO
    format only.
    """

    def __init__(
        self,
        format: Param[str, Arg(help=(
            'Specify the output format as a strftime-like string, using ISO by default.'
        ))] = '%Y-%m-%d %H:%M:%S',
        dos: Param[bool, Arg('-d', help=(
            'Parse numeric timestamps as DOS rather than Unix format.'
        ))] = False,
    ):
        super().__init__(format=format, dos=dos)

    @staticmethod
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

    def _format(self, dt: datetime) -> str:
        return dt.strftime(self.args.format)

    def _extract_timezone(self, data: str):
        def extract(match: re.Match[str]):
            nonlocal zone
            if zone is not None:
                raise ValueError
            h = int(h) if (h := match['h']) else 0
            m = int(m) if (m := match['m']) else 0
            zone = timedelta(hours=h, minutes=m)
            if match['p'] == '-':
                zone = -zone
            return ''
        zone = None
        data = re.sub(_TIMEZONE_PATTERN, extract, data)
        data = re.sub('\\s{2,}', ' ', data).strip()
        return data, zone

    @unicoded
    def process(self, data: str) -> str:
        data = data.strip()

        # replace colons (i.e. for exiftool dates: 2017:01:01)
        if len(data) > 10 and data[4] == ':' and data[7] == ':':
            data = F'{data[0:4]}-{data[5:7]}-{data[8:]}'

        # strips Z at end (i.e. 20171022055144Z)
        if data.endswith('Z'):
            data = data[:-1]

        if data.startswith('0x'):
            try:
                data = str(int(data, 16))
            except Exception:
                pass

        # parses timestamps and dates without much format
        if data.isdigit():
            time_stamp = int(data)
            if len(data) > 14:
                raise Exception('cannot parse all-numeric string as date: %s' % data)
            elif len(data) == 14:
                # i.e. 20111020193727
                return self._format(datetime.strptime(data, '%Y%m%d%H%M%S'))
            elif len(data) == 13:
                # i.e. 1458016535000
                time_stamp //= 1000
                data = data[:-3]
            if self.args.dos:
                return self._format(self.dostime(time_stamp))
            else:
                return self._format(date_from_timestamp(time_stamp))

        try:
            data, time_delta = self._extract_timezone(data)
        except ValueError:
            return data

        for f in _DATETIME_PATTERNS:
            try:
                dt = datetime.strptime(data, f)
            except ValueError:
                continue
            return self._format(dt if time_delta is None else dt - time_delta)

        return data
