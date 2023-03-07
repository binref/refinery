#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, unquote, quote

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
        def fix(string):
            return quote(unquote(string))
        keep = self.args.keep
        parsed = urlparse(data)
        if not parsed.scheme or not parsed.netloc:
            return None
        new_query = '&'.join(F'{key}={fix(value)}' for key, value in parse_qsl(parsed.query))
        replacements = dict(
            netloc=parsed.netloc.lower(),
            params=fix(parsed.params),
            path=fix(parsed.path),
            query=new_query,
            fragment=fix(parsed.fragment),
        )
        if keep < 2:
            replacements.update(fragment='')
            if keep < 1:
                replacements.update(params='', query='')
        return urlunparse(parsed._replace(**replacements))
