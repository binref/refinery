from __future__ import annotations

import plistlib

from refinery.units.formats import JSONEncoderUnit


class plist(JSONEncoderUnit):
    """
    Parses Apple property list (plist) files and converts them to JSON. Property lists are a
    serialization format used extensively in macOS, iOS, and other Apple platforms to store
    configuration data, application preferences, and structured metadata. This unit supports both
    the binary plist format `bplist00` and XML plist format. The reverse operation converts JSON
    input back to binary plist format.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
        from refinery.lib.id import is_likely_plist
        return is_likely_plist(data)

    def process(self, data):
        result = plistlib.loads(data)
        return self.to_json(result)

    def reverse(self, data):
        from refinery.lib.json import loads
        return plistlib.dumps(loads(data), fmt=plistlib.FMT_BINARY)
