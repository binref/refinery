from __future__ import annotations

from urllib.parse import parse_qsl, quote, unquote, urlparse, urlunparse

from refinery.lib.types import Param
from refinery.units import Arg, Unit


class urlfix(Unit):
    """
    Removes fragments, query strings, and parameters from input URLs. It also correctly escapes all
    characters in the URL path component and normalizes the network location part to lowercase. Note
    that URLs without a scheme will not be recognized as valid URLs; chunks that do not look like a
    URL will be swallowed and not return any output.
    """
    def __init__(
        self,
        meta: Param[bool, Arg.Switch('-m', help='Extract the query string parameters as metadata.')] = False,
        keep: Param[int, Arg.Counts('-k', help=(
            'If specified once, keeps the it keeps the URL params and query string. If specified '
            'twice, it keeps the URL fragment as well. At this level, the unit still filters out '
            'anything that does not parse as a URL.'
        ))] = 0
    ):
        super().__init__(keep=keep, meta=meta)

    def process(self, data):
        def fix(string):
            return quote(unquote(string))
        keep = self.args.keep
        meta = self.args.meta
        parsed = urlparse(data.decode(self.codec))
        if not parsed.scheme or not parsed.netloc:
            return None
        query_dict = {key: unquote(value) for key, value in parse_qsl(parsed.query)}
        query_string = '&'.join(F'{key}={quote(value)}' for key, value in query_dict.items())
        replacements = dict(
            netloc=parsed.netloc.lower(),
            params=fix(parsed.params),
            path=fix(parsed.path),
            query=query_string,
            fragment=fix(parsed.fragment),
        )
        if keep < 2:
            replacements.update(fragment='')
            if keep < 1:
                replacements.update(params='', query='')
        url = urlunparse(parsed._replace(**replacements))
        url = url.encode(self.codec)
        if meta:
            url = self.labelled(url, **query_dict)
        return url
