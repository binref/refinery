from __future__ import annotations

from refinery.lib.types import Param
from refinery.units import Arg, Unit
from refinery.units.formats.pe.pemeta import pemeta
from refinery.units.sinks.ppjson import ppjson


class pkcs7sig(Unit):
    """
    Converts PKCS7 encoded signatures into a human-readable JSON representation. This can be used
    to parse authenticode signatures appended to files that are not PE files to get the same output
    that is produced by the pemeta unit. For example, this can be used to parse the code signature
    embedded in MSI files as follows:

        emit sample.msi | xtmsi Meta/DigitalSignature | pkcs7sig
    """
    def __init__(self, tabular: Param[bool, Arg('-t', help='Print information in a table rather than as JSON')] = False):
        super().__init__(tabular=tabular)

    def process(self, data):
        json = pemeta.parse_signature(data)
        yield from ppjson(tabular=self.args.tabular)._pretty_output(json)
