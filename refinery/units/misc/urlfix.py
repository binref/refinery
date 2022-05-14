#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Optional
from urllib.parse import urlparse, urlunparse

from refinery.units import Arg, Unit
from refinery.lib.decorators import unicoded


class urlfix(Unit):
    """
    Removes fragments, query strings, and parameters from input URLs. URLs that do not have a scheme
    will not be recognized as valid URLs.
    """
    def __init__(
        self,
        keep: Arg('-k', action='count', help=(
            'If specified once, keeps the it keeps the URL params and query string. If specified '
            'twice, it keeps the URL fragment as well. At this level, the unit still filters out '
            'anything that does not parse as a URL.'
        )) = 0
    ):
        super().__init__(keep=keep)

    @unicoded
    def process(self, data: str) -> Optional[str]:
        keep = self.args.keep
        parsed = urlparse(data)
        if not parsed.scheme or not parsed.netloc:
            return None
        if keep < 2:
            parsed = parsed._replace(fragment='')
            if keep < 1:
                parsed = parsed._replace(params='', query='')
        return urlunparse(parsed)
