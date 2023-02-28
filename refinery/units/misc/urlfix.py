#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Optional
from urllib.parse import urlparse, urlunparse, unquote, quote

from refinery.units import Arg, Unit
from refinery.lib.decorators import unicoded


class urlfix(Unit):
    """
    Removes fragments, query strings, and parameters from input URLs. It also correctly escapes all
    characters in the URL path component and normalizes the network location part to lowercase. Note
    that URLs without a scheme will not be recognized as valid URLs; chunks that do not look like a
    URL will be swallowed and not return any output.
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
        replacements = dict(
            path=quote(unquote(parsed.path)),
            netloc=parsed.netloc.lower())
        if keep < 2:
            replacements.update(fragment='')
            if keep < 1:
                replacements.update(params='', query='')
        return urlunparse(parsed._replace(**replacements))
