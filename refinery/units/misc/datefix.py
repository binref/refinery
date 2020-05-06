#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from re import compile as re_compile
from datetime import datetime, timedelta

from .. import arg, Unit
from ...lib.decorators import linewise


class datefix(Unit):
    """
    Parses all kinds of date _formats and unifies them into the same format.
    """

    _FORMATS = [
        '%B %dth %Y %H:%M:%S (UTC)',  # November 27th 2019 17:37:02 (UTC)
        '%Y-%m-%dT%H:%M:%S',          # 2010-03-15T06:27:50
        '%Y-%m-%d %H:%M:%S',          # iso (2010-03-15 06:27:50.000000)
        '%Y-%m-%d %H:%M:%SZ%f',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%SZ%f',
        '%a %b %d %Y %H:%M:%S',       # Thu Apr 24 2014 12:32:21
    ]

    _TIMEZONE_REGEXES = [re_compile(p) for p in [
        R'([+-])(\d{2})(\d{2})$',           # Thu Apr 24 2014 12:32:21 GMT-0700
        R'([+-])(\d{2}):(\d{2})$',          # 2017:09:11 23:47:22+02:00
        R'GMT([+-])(\d{2})(\d{2}) \(.+\)$'  # Thu Apr 24 2014 12:32:21 GMT-0700 (PDT)
    ]]

    def __init__(
        self,
        format: arg(help='Specify the output format as a strftime-like string, using ISO by default.') = '%Y-%m-%d %H:%M:%S',
        dos: arg('-d', help='Parse timestamps in DOS rather than Unix format.') = False
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

    def _extract_timezone(self, data):
        for r in self._TIMEZONE_REGEXES:
            m = r.search(data)
            if not m:
                continue
            pm = m[1]
            td = timedelta(
                hours=int(m[2]), minutes=int(m[3]))
            if pm == '-':
                td = -td
            return data[:-len(m[0])].strip(), td

        return data, None

    @linewise
    def process(self, data: str) -> str:
        data = data.strip()

        # replace colons (i.e. for exiftool dates: 2017:01:01)
        if len(data) > 10 and data[4] == ':' and data[7] == ':':
            data = F'{data[0:4]}-{data[5:7]}-{data[8:]}'

        # strips Z at end (i.e. 20171022055144Z)
        if data.endswith('Z'):
            data = data[:-1]

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
                return self._format(datetime.utcfromtimestamp(time_stamp))

        data, time_delta = self._extract_timezone(data)

        for f in self._FORMATS:
            try:
                dt = datetime.strptime(data, f)
            except ValueError:
                continue
            return self._format(dt if time_delta is None else dt - time_delta)

        return data
