from __future__ import annotations

from refinery.lib.lnk import LnkFile
from refinery.lib.types import Param
from refinery.units.formats import Arg, JSONTableUnit


class lnk(JSONTableUnit):
    """
    Parse Windows Shortcuts (LNK files) and returns the parsed information in JSON format.
    """

    _PATHS = {
        'data'        : ...,
        'target_path' : ...,
        'header'      : {'creation_time', 'accessed_time', 'modified_time', 'show_command'},
        'link_info'   : {'local_base_path', 'volume_id', 'common_network_relative_link'},
    }

    def __init__(
        self,
        details: Param[bool, Arg('-d', help=(
            'Print all details; some properties are hidden by default.'
        ))] = False,
        tabular=False,
    ):
        super().__init__(tabular=tabular, details=details)

    def json(self, data):
        parsed = LnkFile(data).__json__()
        if not self.args.details:
            paths = self._PATHS
            noise = [key for key in parsed if key not in paths]
            for key in noise:
                del parsed[key]
            for path, scope in paths.items():
                if scope is (...):
                    continue
                try:
                    section = parsed[path]
                except KeyError:
                    continue
                noise = [key for key in section if key not in scope]
                for key in noise:
                    del section[key]
        return parsed

    @classmethod
    def handles(cls, data):
        return data[:20] == B'L\0\0\0\01\x14\02\0\0\0\0\0\xC0\0\0\0\0\0\0F'
