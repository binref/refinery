from __future__ import annotations

from refinery.lib.types import Param
from refinery.lib.unquarantine import Vendor, unquarantine
from refinery.units import Arg, Unit


class unq(Unit):
    """
    Attempts to extract the original file from an antivirus quarantine container.

    When no vendor is specified, the unit first tries to identify the quarantine format by magic
    bytes. If that fails, it tries all known decoders and returns the first result that produces
    a recognisable file format.
    """

    def __init__(
        self,
        vendor: Param[str | None, Arg.Option(metavar='vendor', choices=Vendor, help=(
            'Select an AV vendor to forego auto-detection. The choices are: {choices}'
        ))] = None,
    ):
        super().__init__(vendor=Arg.AsOption(vendor, Vendor))

    @classmethod
    def handles(cls, data) -> bool | None:
        from refinery.lib.id import get_quarantine_format
        if get_quarantine_format(data) is not None:
            return True
        return None

    def process(self, data):
        vendor: Vendor = self.args.vendor
        result = unquarantine(data, vendor=vendor)
        meta = {'vendor': result.vendor}
        if result.filename:
            meta['name'] = result.filename
        if result.threat:
            meta['threat'] = result.threat
        return self.labelled(result.data, **meta)
